use std::collections::{HashMap, HashSet};
use std::mem::replace;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use argon2::{Config as ArgonConfig, Error as ArgonError, hash_encoded};
// use ed25519_dalek::{PublicKey, Signature};
use rand::{CryptoRng, Rng, RngCore, thread_rng};
use rand::distributions::Alphanumeric;
use regex::Regex;
use rocket::tokio::spawn;
use rocket::tokio::time::sleep;
use std::sync::{Mutex, RwLock};

use crate::*;

declare_logger!([pub] FAILED_LOGINS);

/// The public component of a user credential
///
/// For passwords, it's their hash
// /// For keys, its the public key
#[derive(Debug)]
pub enum Credential {
	PasswordHash(String),
	// Key(PublicKey),
}


struct FailedLoginAttempt {
	running_count: u8,
	time: Instant
}


pub enum LoginResult {
	Ok,
	/// Username does not exist
	NonexistentUser,
	/// The given credential challenge is not correct
	BadCredentialChallenge,
	// /// The user cannot be authorized using the given credential challenge.
	// /// ie. Giving a password when the user uses key based verification and vice-versa
	// UnexpectedCredentials,
	// /// The given credential challenge has been used before.
	// /// Only returned on key based verification
	// UsedChallenge,
	/// The given user cannot login right now as their account is being locked out
	LockedOut
}

pub enum UserCreationError {
	UsernameInUse,
	PasswordHasWhitespace,
	/// Username does not pass the password regex
	BadPassword,
	/// Error using argon hashing (pretty rare)
	ArgonError(ArgonError),
	/// Username is not alphanumeric
	BadUsername
}


/// Identification of a session
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct SessionID([char; 32]);


pub struct SessionData {
	/// Time that the session was created
	creation_time: Instant,
	/// Username of user that created it
	owning_user: String
}


/// Manages user authentication and user creation
pub struct Logins {
	user_cred_map: RwLock<HashMap<String, Credential>>,
	lockout_time: Duration,
	max_fails: u8,
	failed_logins: RwLock<HashMap<String, FailedLoginAttempt>>,
	// used_challenges: Mutex<HashSet<String>>,
	// key_challenge_prefix: String,
	argon2_config: ArgonConfig<'static>,
	salt_len: u8,
	min_username_len: u8,
	max_username_len: u8,
	password_regex: Regex,
	// pub(crate) user_home_template_path: PathBuf,
	tmp_reserved_names: Mutex<HashSet<String>>
}


/// Manages user sessions
pub struct Sessions {
	user_session_map: RwLock<HashMap<String, Arc<SessionID>>>,
	session_user_map: RwLock<HashMap<Arc<SessionID>, String>>,
	sessions: RwLock<HashMap<Arc<SessionID>, SessionData>>,
	pub(crate) max_session_duration: Duration
}


pub struct UserCreationPromise<'a> {
	username: String,
	password_hash: String,
	logins: &'a Logins
}


impl<'a> Drop for UserCreationPromise<'a> {
	fn drop(&mut self) {
		self.logins.tmp_reserved_names.lock().unwrap().remove(&self.username);
	}
}


impl<'a> UserCreationPromise<'a> {
	pub fn finalize(self) {
		self.logins.user_cred_map.write().unwrap().insert(self.username.clone(), Credential::PasswordHash(self.password_hash.clone()));
	}
}


pub struct UserDeletionPromise<'a> {
	username: String,
	logins: &'a Logins
}


impl<'a> UserDeletionPromise<'a> {
	pub fn finalize(self) {
		self.logins.user_cred_map.write().unwrap().remove(&self.username);
	}
}


impl From<ArgonError> for UserCreationError {
	fn from(e: ArgonError) -> Self {
		Self::ArgonError(e)
	}
}


#[derive(Debug)]
pub enum ParseUserPasswordError {
	MissingPasswordHash{ line: usize, username: String },
	DuplicateUsername{ line: usize, username: String }
}


impl Logins {
	pub fn parse_user_password_map(data: String) -> Result<HashMap<String, Credential>, ParseUserPasswordError> {
		let mut map = HashMap::new();
		let lines = data.split('\n');

		for (i, line) in lines.enumerate() {
			let mut split = line.split_whitespace();
			let username = if let Some(x) = split.next() { x } else { continue };
			let password = split.next().ok_or(ParseUserPasswordError::MissingPasswordHash { line: i, username: username.into() })?;

			if map.insert(username.to_string(), Credential::PasswordHash(password.into())).is_some() {
				return Err(ParseUserPasswordError::DuplicateUsername { line: i, username: username.into() })
			}
		}

		Ok(map)
	}

	/// Creates a Logins instance that has a separate task that performs occasional cleanups
	pub fn new(
		user_cred_map: HashMap<String, Credential>,
		lockout_time: Duration,
		max_fails: u8,
		salt_len: u8,
		min_username_len: u8,
		max_username_len: u8,
		cleanup_delay: u32,
		password_regex: Regex,
	) -> Arc<Self> {
		if max_username_len < min_username_len {
			panic!("max_username_len is smaller than min_username_len!")
		}

		let out = Arc::new(Self {
			user_cred_map: RwLock::new(user_cred_map),
			lockout_time,
			max_fails,
			failed_logins: Default::default(),
			argon2_config: Default::default(),
			salt_len,
			min_username_len,
			max_username_len,
			password_regex,
			tmp_reserved_names: Default::default()
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_expired();
			}
		});

		out
	}

	/// Remove failed login attempts that are expired
	fn prune_expired(&self) {
		let mut writer = self.failed_logins.write().unwrap();
		let old_fails = replace(writer.deref_mut(), HashMap::new());
		for (username, fail) in old_fails {
			if fail.time.elapsed() < self.lockout_time {
				writer.insert(username, fail);
			}
		}
	}

	/// Returns a UserCreationPromise
	/// Call finalize on it to permanently add the user,
	/// otherwise, the username will be reserved for as long as the promise is alive
	///
	/// New users can only be made with a password, not a key
	pub fn add_user(&self, username: String, password: String) -> Result<UserCreationPromise, UserCreationError> {
		if username.chars().any(char::is_whitespace) {
			return Err(UserCreationError::PasswordHasWhitespace)
		}

		if username.len() < self.min_username_len as usize ||
			username.len() > self.max_username_len as usize ||
			!username.chars().all(char::is_alphanumeric)
		{
			return Err(UserCreationError::BadUsername)
		}

		if !self.password_regex.is_match(password.as_str()) {
			return Err(UserCreationError::BadPassword)
		}

		if self.tmp_reserved_names.lock().unwrap().contains(&username) || self.user_cred_map.read().unwrap().contains_key(&username) {
			return Err(UserCreationError::UsernameInUse)
		}

		Ok(
			UserCreationPromise {
				username,
				password_hash: hash_encoded(
							password.as_bytes(),
							thread_rng()
								.sample_iter(&Alphanumeric)
								.take(self.salt_len as usize)
								.collect::<Vec<_>>()
								.as_slice(),
							&self.argon2_config
						)?,
				logins: self
			}
		)
	}

	pub fn delete_user(&self, username: String) -> Option<UserDeletionPromise> {
		if self.user_cred_map.read().unwrap().contains_key(&username) {
			Some(UserDeletionPromise {
				username,
				logins: self
			})
		} else {
			None
		}
	}

	/// Try to login with the given credentials
	pub fn try_login_password(&self, username: &String, password: String) -> LoginResult {
		let reader = self.failed_logins.read().unwrap();

		if let Some(fail) = reader.get(username) {
			if fail.running_count >= self.max_fails {
				if fail.time.elapsed() <= self.lockout_time {
					return LoginResult::LockedOut
				} else {
					drop(reader);
					self.failed_logins.write().unwrap().remove(username);
				}
			} else if fail.time.elapsed() > self.lockout_time {
				// The last fail was too long ago
				self.failed_logins.write().unwrap().remove(username);
			}
		} else {
			drop(reader)
		}

		match self.user_cred_map.read().unwrap().get(username) {
			Some(Credential::PasswordHash(hash)) =>
				if argon2::verify_encoded(hash.as_str(), password.as_bytes()).unwrap() {

					if self.failed_logins.read().unwrap().contains_key(username) {
						self.failed_logins.write().unwrap().remove(username);
					}

					LoginResult::Ok
				} else {
					let mut writer = self.failed_logins.write().unwrap();

					if let Some(fail) = writer.get_mut(username) {
						fail.running_count += 1;
						fail.time = Instant::now();
						if fail.running_count == self.max_fails {
							FAILED_LOGINS.warn(username.clone(), None);
						}
					} else {
						writer.insert(username.clone(), FailedLoginAttempt {
							running_count: 1,
							time: Instant::now()
						});
					}

					LoginResult::BadCredentialChallenge
				},
			// Some(Credential::Key(_)) => LoginResult::UnexpectedCredentials,
			None => LoginResult::NonexistentUser
		}
	}

	// /// Try to login with the given credentials
	// pub fn try_login_key(&self, username: &String, challenge: String, signature: Signature) -> LoginResult {
	// 	match self.user_cred_map.read().unwrap().get(username) {
	// 		Some(Credential::PasswordHash(_)) => LoginResult::UnexpectedCredentials,
	// 		Some(Credential::Key(key)) => {
	// 			if !challenge.starts_with(&self.key_challenge_prefix) {
	// 				return LoginResult::BadCredentialChallenge
	// 			}

	// 			let mut used_challenges = self.used_challenges.lock().unwrap();
	// 			if used_challenges.contains(&challenge) {
	// 				LoginResult::UsedChallenge
	// 			} else if key.verify_strict(challenge.as_bytes(), &signature).is_ok() {
	// 				used_challenges.insert(challenge);
	// 				LoginResult::Ok
	// 			} else {
	// 				LoginResult::BadCredentialChallenge
	// 			}
	// 		}
	// 		None => LoginResult::NonexistentUser
	// 	}
	// }
}


impl SessionID {
	/// Create a random session ID
	///
	/// May or may not already exist
	pub fn new<T: CryptoRng + RngCore>(rand_gen: &mut T) -> Self {
		let mut arr = [char::default(); 32];

		rand_gen
			.sample_iter(&Alphanumeric)
			.take(32)
			.enumerate()
			.for_each(
				|(i, c)| { arr[i] = char::from(c) }
			);

		Self(arr)
	}
}


impl ToString for SessionID {
	fn to_string(&self) -> String {
		self.0.iter().cloned().collect()
	}
}


impl TryFrom<String> for SessionID {
	type Error = String;

	fn try_from(value: String) -> Result<Self, Self::Error> {
		Ok(Self(value.to_string().chars().collect::<Vec<_>>().try_into().map_err(|_| value)?))
	}
}


impl Sessions {
	/// Creates a Sessions instance that has a separate task that performs occasional cleanups
	pub fn new(max_session_duration: Duration, cleanup_delay: u32) -> Arc<Self> {
		let out = Arc::new(Self {
			user_session_map: Default::default(),
			session_user_map: Default::default(),
			sessions: Default::default(),
			max_session_duration
		});

		let out_clone = out.clone();
		spawn(async move {
			let duration = Duration::from_secs(cleanup_delay as u64);
			loop {
				sleep(duration).await;
				out_clone.prune_expired();
			}
		});

		out
	}

	/// Create a new session for the given user
	///
	/// If the user has already opened a session and it has not expired yet, it will be returned
	///
	/// Does not check if the user has been authenticated
	pub fn create_session(&self, username: String) -> Arc<SessionID> {
		if let Some(x) = self.user_session_map.read().unwrap().get(&username) {
			return x.clone()
		}

		let mut writer = self.sessions.write().unwrap();
		let mut session_id;

		{
			let mut rand_gen = thread_rng();
			session_id = SessionID::new(&mut rand_gen);

			while writer.contains_key(&session_id) {
				session_id = SessionID::new(&mut rand_gen)
			}
		}

		let arc_session_id = Arc::new(session_id);
		writer.insert(arc_session_id.clone(), SessionData {
			creation_time: Instant::now(),
			owning_user: username.clone()
		});
		drop(writer);

		self.user_session_map.write().unwrap().insert(username.clone(), arc_session_id.clone());
		self.session_user_map.write().unwrap().insert(arc_session_id.clone(), username);

		arc_session_id
	}

	/// Remove expired sessions
	fn prune_expired(&self) {
		let mut session_writer = self.sessions.write().unwrap();
		let old_sessions = replace(session_writer.deref_mut(), HashMap::new());
		let mut user_session_writer = self.user_session_map.write().unwrap();
		let mut session_user_writer = self.session_user_map.write().unwrap();

		for (session_id, session_data) in old_sessions {
			if session_data.creation_time.elapsed() > self.max_session_duration {
				user_session_writer.remove(&session_data.owning_user);
				session_user_writer.remove(&session_id);
			} else {
				session_writer.insert(session_id, session_data);
			}
		}
	}

	/// Does the given session exist and is not expired?
	pub fn is_valid_session(&self, session_id: &SessionID) -> bool {
		self.sessions.read().unwrap().contains_key(session_id)
	}

	/// Get the username that owns the given session
	pub fn get_session_owner(&self, session_id: &SessionID) -> Option<String> {
		self.session_user_map.read().unwrap().get(session_id).cloned()
	}
}