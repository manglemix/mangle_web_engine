use std::time::Duration;

use regex::Regex;
use rocket::{FromForm, async_trait};
use rocket::form::Form;
use rocket::request::{FromRequest, Outcome};
use mangle_rust_utils::default_error;

mod singletons;

use rocket_db_pools::sqlx::error::DatabaseError;
use rocket_db_pools::sqlx::sqlite::SqliteError;
use singletons::{Logins, Sessions};
pub use singletons::{FAILED_LOGINS, SessionID};
use crate::{log::*, AppConfig};

use self::singletons::{session_id_to_string, PasswordHash, UsernameError};

use super::*;

use rocket_db_pools::{Database, Connection};
use rocket_db_pools::sqlx::{self, Row};

#[derive(Database)]
#[database("credentials")]
pub struct Credentials(sqlx::SqlitePool);


pub struct AuthenticatedUser {
	pub username: String
}

const SESSION_HEADER_NAME: &str = "Session-Key";


#[async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> rocket::request::Outcome<Self,Self::Error> {
		// TODO Add client ip check
		let mut iter = request.headers().get(SESSION_HEADER_NAME);

        let session_id = if let Some(x) = iter.next() {
			if let Ok(x) = TryInto::<SessionID>::try_into(x.chars().collect::<Vec<char>>()) {
				x
			} else {
				request.local_cache(|| format!("{SESSION_HEADER_NAME} header is not an array of chars"));
				return Outcome::Failure((Status::BadRequest, ()))
			}
		} else {
			request.local_cache(|| format!("{SESSION_HEADER_NAME} header is empty"));
			return Outcome::Failure((Status::BadRequest, ()))
		};

		if iter.next().is_some() {
			request.local_cache(|| format!("{SESSION_HEADER_NAME} header contains multiple items"));
			return Outcome::Failure((Status::BadRequest, ()))
		}

		let auth: &AuthState = request.rocket().state().unwrap();

		if let Some(username) = auth.sessions.get_session_owner(&session_id) {
			Outcome::Success(Self {
				username
			})
		} else {
			request.local_cache(|| format!("{SESSION_HEADER_NAME} header value is either invalid or expired"));
			Outcome::Failure((Status::Unauthorized, ()))
		}
    }
}


pub struct AuthState {
	pub logins: Logins,
	pub sessions: Sessions,
}


impl AuthState {
	pub fn run_cleanups(&self) {
		self.logins.prune_expired();
		self.sessions.prune_expired();
	}
}


pub(crate) fn make_auth_state(config: &AppConfig) -> AuthState {
	AuthState {
		logins: Logins::new(
			Duration::from_secs(config.login_timeout as u64),
			config.max_fails,
			config.salt_len,
			config.min_username_len,
			config.max_username_len,
			Duration::from_secs(config.cleanup_interval as u64),
			unwrap_result_or_default_error!(
				Regex::new(config.password_regex.as_str()),
				"parsing password regex"
			),
			config.password_hash_length
		),
		sessions: Sessions::new(
			Duration::from_secs(config.max_session_duration as u64),
			Duration::from_secs(config.cleanup_interval as u64)
		),
	}
}


#[derive(FromForm)]
pub struct UserForm<'a> {
	username: &'a str,
	password: &'a str
}

/// Try to start a session with a username and password
///
/// If the user has already opened one and it has not expired, it will be returned
#[rocket::post("/login", data = "<form>")]
pub(crate) async fn get_session_with_password<'a>(form: Form<UserForm<'a>>, mut credentials: Connection<Credentials>, auth: &State<AuthState>) -> Response {
	auth.run_cleanups();

	let form = form.into_inner();
	let username = form.username;
	let logins = &auth.logins;
	
	if let Some(remaining_time) = logins.is_user_locked_out(username) {
		return make_response!(Status::Forbidden, format!("Locked out temporarily for {} secs", remaining_time.as_secs()))
	}

	let password = form.password;

	let row = match sqlx::query("SELECT Salt, Hash FROM PasswordUsers WHERE Username = ?")
		.bind(username.clone())
		.fetch_optional(&mut *credentials).await {
			Ok(Some(x)) => x,
			Ok(None) => return make_response!(BadRequest, "User does not exist".into()),
			Err(e) => {
				default_error!(
					e,
					"querying credentials db"
				);
				return make_response!(BUG)
			}
		};
	
	let salt: Vec<u8> = row.get_unchecked("Salt");
	let hash: Vec<u8> = row.get_unchecked("Hash");

	match logins.verify_password(password, salt.as_slice(), hash.as_slice()) {
		Ok(true) => {
			logins.mark_succesful_login(username);
			make_response!(Ok, session_id_to_string(auth.sessions.create_session(username.into())))
		},
		Ok(false) => {
			logins.mark_failed_login(username.into());
			make_response!(Status::Unauthorized, "".into())
		}
		Err(e) => {
			default_error!(
				e,
				"verifying password"
			);
			make_response!(BUG)
		}
	}
}


/// Tries to create a new user, granted the creating user has appropriate abilities
#[rocket::post("/sign_up", data = "<form>")]
pub(crate) async fn make_user<'a>(form: Form<UserForm<'a>>, mut credentials: Connection<Credentials>, auth: &State<AuthState>) -> Response {
	auth.run_cleanups();
	
	let form = form.into_inner();
	let username = form.username;
	let password = form.password;
	let logins = &auth.logins;

	match logins.is_valid_username(&username) {
		Ok(()) => {}
		Err(e) => return make_response!(
			BadRequest,
			match e {
				UsernameError::ContainsWhitespace => "Username contains whitespace",
				UsernameError::Inappropriate => "Username is inappropriate",
				UsernameError::TooShort => "Username is too short",
				UsernameError::TooLong => "Username is too long",
				UsernameError::IsNotAlphanumeric => "Username is not alphanumeric",
			}.into()
		),
	}
	if !logins.is_valid_password(password) {
		return make_response!(BadRequest, "Password does not fit the requirements".into())
	}
	
	let _ = if let Some(x) = logins.reserve_username(username.into()) {
		x
	} else {
		return make_response!(BadRequest, "Username already in use".into())
	};

	let PasswordHash {hash, salt} = match logins.hash_password(password) {
		Ok(x) => x,
		Err(e) => {
			default_error!(
				e,
				"hashing password"
			);
			return make_response!(BUG)
		}
	};

	match sqlx::query("INSERT INTO PasswordUsers (Username, Salt, Hash) VALUES (?, ?, ?)")
		.bind(username.clone())
		.bind(salt)
		.bind(hash)
		.execute(&mut *credentials).await
	{
		Ok(_) => {}
		Err(e) => return match e.as_database_error() {
            Some(e) => {
                let e: &SqliteError = e.downcast_ref();

                let string;
                let code = match e.code().unwrap() {
                    std::borrow::Cow::Borrowed(x) => x,
                    std::borrow::Cow::Owned(x) => {
                        string = x;
                        string.as_str()
                    }
                };

                match code {
                    "1555" => (Status::BadRequest, "Username is already in use".into()),
                    _ => {
                        default_error!(
                            e,
                            "inserting into PasswordUsers"
                        );
                        (Status::InternalServerError, crate::apps::BUG_MESSAGE.into())
                    }
                }
            }
            None => {
                default_error!(
                    e,
                    "inserting into PasswordUsers"
                );
                (Status::InternalServerError, crate::apps::BUG_MESSAGE.into())
            }
        }
	}

	make_response!(Ok, session_id_to_string(auth.sessions.create_session(username.into())))
}

// /// Tries to delete the user that is currently logged in
// #[rocket::post("/delete_my_account")]
// pub(crate) async fn delete_user(cookies: &CookieJar<'_>, globals: &State<AuthState>) -> Response {
// 	let session_id = match check_session_id!(globals.sessions, cookies) {
// 		Some(x) => x,
// 		None => missing_session!()
// 	};

// 	let username = match globals.sessions.get_session_owner(&session_id) {
// 		Some(username) => username,
// 		None => {
// 			error!("Session-ID was valid but not associated with a user!");
// 			return make_response!(BUG)
// 		}
// 	};

// 	let promise = match globals.logins.delete_user(username.clone()) {
// 		Some(x) => x,
// 		None => return make_response!(BadRequest, "User does not exist")
// 	};

// 	promise.finalize();
// 	make_response!(Ok, "User deleted successfully")
// }
