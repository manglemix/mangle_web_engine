use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::ops::DerefMut;
use std::time::{Duration, Instant};

use argon2::{Config as ArgonConfig, Error as ArgonError, hash_raw, verify_raw};
use rand::{CryptoRng, Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use regex::Regex;
use simple_logger::Logger;
use std::sync::{Mutex, RwLock};
use rustrict::CensorStr;

use bimap::BiMap;

pub static FAILED_LOGINS: Logger = Logger::new();


struct FailedLoginAttempt {
	running_count: u8,
	time: Instant
}


pub struct PasswordHash {
	pub hash: Vec<u8>,
	pub salt: Vec<u8>
}


pub struct UsernameReservation<'a> {
	logins: &'a Logins,
	username: String
}


impl<'a> Drop for UsernameReservation<'a> {
    fn drop(&mut self) {
        self.logins.tmp_reserved_names.lock().unwrap().remove(&self.username);
    }
}


pub type SessionID = [char; 32];


/// Identification of a session
struct SessionData {
	id: SessionID,
	creation_time: Instant,
	renew_count: u8
}


impl Borrow<SessionID> for SessionData {
    fn borrow(&self) -> &SessionID {
        &self.id
    }
}


impl std::hash::Hash for SessionData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}


impl PartialEq for SessionData {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}


impl Eq for SessionData {}


/// Manages user authentication and user creation
pub struct Logins {
	lockout_time: Duration,
	max_fails: u8,
	failed_logins: RwLock<HashMap<String, FailedLoginAttempt>>,
	argon2_config: ArgonConfig<'static>,
	salt_len: u8,
	min_username_len: u8,
	max_username_len: u8,
	password_regex: Regex,
	tmp_reserved_names: Mutex<HashSet<String>>,
	cleanup_interval: Duration,
	last_cleanup_time: RwLock<Instant>
}


/// Manages user sessions
pub struct Sessions {
	user_session_map: RwLock<BiMap<String, SessionData>>,
	pub(crate) max_session_duration: Duration,
	cleanup_interval: Duration,
	last_cleanup_time: RwLock<Instant>,
	max_renew_count: u8
}


pub enum UsernameError {
	ContainsWhitespace,
	Inappropriate,
	TooShort,
	TooLong,
	IsNotAlphanumeric
}


impl Logins {
	/// Creates a Logins instance that has a separate task that performs occasional cleanups
	pub fn new(
		lockout_time: Duration,
		max_fails: u8,
		salt_len: u8,
		min_username_len: u8,
		max_username_len: u8,
		cleanup_interval: Duration,
		password_regex: Regex,
		hash_length: u8
	) -> Self {
		if max_username_len < min_username_len {
			panic!("max_username_len is smaller than min_username_len!")
		}

		let mut argon2_config: ArgonConfig = Default::default();
		argon2_config.hash_length = hash_length as u32;

		Self {
			lockout_time,
			max_fails,
			failed_logins: Default::default(),
			argon2_config,
			salt_len,
			min_username_len,
			max_username_len,
			password_regex,
			cleanup_interval,
			tmp_reserved_names: Default::default(),
			last_cleanup_time: RwLock::new(Instant::now())
		}
	}

	/// Remove failed login attempts that are expired
	pub fn prune_expired(&self) {
		if self.last_cleanup_time.read().unwrap().elapsed() < self.cleanup_interval {
			return
		}

		*self.last_cleanup_time.write().unwrap() = Instant::now();

		let mut writer = self.failed_logins.write().unwrap();
		let old_fails = replace(writer.deref_mut(), HashMap::new());
		
		for (username, fail) in old_fails {
			if fail.time.elapsed() < self.lockout_time {
				writer.insert(username, fail);
			}
		}
	}

	pub fn is_user_locked_out(&self, username: &str) -> Option<Duration> {
		if let Some(attempt) = self.failed_logins.read().unwrap().get(username) {
			let elapsed_time = attempt.time.elapsed();

			if attempt.running_count >= self.max_fails && elapsed_time < self.lockout_time {
				Some(self.lockout_time - elapsed_time)
			} else {
				None
			}
		} else {
			None
		}
	}

	pub fn mark_failed_login(&self, username: String) {
		let mut writer = self.failed_logins.write().unwrap();

		let attempt = match writer.remove(&username) {
			Some(mut attempt) => {
				if attempt.running_count >= self.max_fails {
					attempt.running_count = 1;
				} else {
					attempt.running_count += 1;
				}
				attempt.time = Instant::now();
				attempt
			}
			None => FailedLoginAttempt { running_count: 1, time: Instant::now() }
		};

		writer.insert(username, attempt);
	}

	pub fn mark_succesful_login(&self, username: &str) {
		self.failed_logins.write().unwrap().remove(username);
	}

	pub fn reserve_username(&self, username: String) -> Option<UsernameReservation> {
		let mut lock = self.tmp_reserved_names.lock().unwrap();

		if !lock.insert(username.clone()) {
			return None
		}

		Some(UsernameReservation { logins: self, username })
	}

	pub fn is_valid_username(&self, username: &str) -> Result<(), UsernameError> {
		if username.chars().any(char::is_whitespace) {
			return Err(UsernameError::ContainsWhitespace)
		}
		if username.len() < self.min_username_len as usize {
			return Err(UsernameError::TooShort)
		}
		if username.len() > self.max_username_len as usize {
			return Err(UsernameError::TooLong)
		}
		if !username.chars().all(char::is_alphanumeric) {
			return Err(UsernameError::IsNotAlphanumeric)
		}
		if username.is_inappropriate() {
			return Err(UsernameError::Inappropriate)
		}
		return Ok(())
	}

	pub fn is_valid_password(&self, password: &str) -> bool {
		self.password_regex.is_match(password)
	}

	pub fn hash_password(&self, password: &str) -> Result<PasswordHash, ArgonError> {
		let salt = thread_rng()
			.sample_iter(rand::distributions::Standard)
			.take(self.salt_len as usize)
			.collect::<Vec<_>>();

		Ok(
			PasswordHash {
				hash: hash_raw(password.as_bytes(), salt.as_slice(), &self.argon2_config)?,
				salt
			}
		)
	}

	pub fn verify_password(&self, password: &str, true_salt: &[u8], true_hash: &[u8]) -> Result<bool, ArgonError> {
		Ok(
			verify_raw(password.as_bytes(), true_salt, true_hash, &self.argon2_config)?
		)
	}

	// pub fn delete_user(&self, username: String) -> Option<UserDeletionPromise> {
	// 	if self.user_cred_map.read().unwrap().contains_key(&username) {
	// 		Some(UserDeletionPromise {
	// 			username,
	// 			logins: self
	// 		})
	// 	} else {
	// 		None
	// 	}
	// }
}



fn make_session_id(rand_gen: &mut (impl CryptoRng + RngCore)) -> SessionID {
	let mut arr = [char::default(); 32];

	rand_gen
		.sample_iter(&Alphanumeric)
		.take(32)
		.enumerate()
		.for_each(
			|(i, c)| { arr[i] = char::from(c) }
		);

	arr
}


pub fn session_id_to_string(id: SessionID) -> String {
	id.into_iter().collect()
}


impl Sessions {
	/// Creates a Sessions instance that has a separate task that performs occasional cleanups
	pub fn new(max_session_duration: Duration, cleanup_interval: Duration, max_renew_count: u8) -> Self {
		Self {
			user_session_map: Default::default(),
			cleanup_interval,
			max_session_duration,
			last_cleanup_time: RwLock::new(Instant::now()),
			max_renew_count
		}
	}

	// pub fn has_session(&self, username: &str) -> bool {
	// 	self.user_session_map.read().unwrap().contains_left(username)
	// }

	/// Create a new session for the given user, replacing an existing one if it exists
	///
	/// Does not check if the user has been authenticated
	pub fn create_session(&self, username: String) -> SessionID {
		let mut writer = self.user_session_map.write().unwrap();
		let mut rand_gen = thread_rng();
		let mut session_id = make_session_id(&mut rand_gen);

		let mut session_data = SessionData {
			id: session_id.clone(),
			creation_time: Instant::now(),
			renew_count: 0
		};

		while writer.contains_right(&session_data) {
			session_id = make_session_id(&mut rand_gen);
			session_data.id = session_id.clone();
		}

		writer.insert(username, session_data);

		session_id
	}

	pub fn renew_session(&self, username: &str) -> Option<u8> {
		let mut writer = self.user_session_map.write().unwrap();
		let (username, mut data) = writer.remove_by_left(username)?;
		
		if data.renew_count >= self.max_renew_count {
			None
		} else {
			data.renew_count += 1;
			data.creation_time = Instant::now();
			let renew_count = data.renew_count;
			writer.insert(username, data);
			Some(self.max_renew_count - renew_count)
		}
	}

	pub fn remove_session(&self, username: &str) {
		self.user_session_map.write().unwrap().remove_by_left(username);
	}

	/// Remove expired sessions
	pub fn prune_expired(&self) {
		if self.last_cleanup_time.read().unwrap().elapsed() < self.cleanup_interval {
			return
		}

		*self.last_cleanup_time.write().unwrap() = Instant::now();

		let mut writer = self.user_session_map.write().unwrap();
		let old_sessions = replace(writer.deref_mut(), BiMap::new());

		for (username, session_data) in old_sessions {
			if session_data.creation_time.elapsed() >= self.max_session_duration {
				writer.remove_by_right(&session_data);
			} else {
				writer.insert(username, session_data);
			}
		}
	}

	pub fn get_session_owner(&self, id: &SessionID) -> Option<String> {
		self.user_session_map.read().unwrap().get_by_right(id).cloned()
	}
}