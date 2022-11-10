/// Methods that involve user authentication
use std::ops::Add;
use std::time::SystemTime;

use rocket::FromForm;
use rocket::form::Form;
use rocket::http::{Cookie, CookieJar};
use rocket::time::OffsetDateTime;

use crate::methods::AuthState;
use crate::singletons::{LoginResult, UserCreationError};

use super::*;


#[derive(FromForm)]
pub struct UserForm {
	username: String,
	password: String
}

/// Try to start a session with a username and password
///
/// If the user has already opened one and it has not expired, it will be returned
#[rocket::post("/login", data = "<form>")]
pub(crate) async fn get_session_with_password(form: Form<UserForm>, cookies: &CookieJar<'_>, globals: &AuthState) -> Response {
	let form = form.into_inner();

	match globals.logins.try_login_password(&form.username, form.password) {
		LoginResult::Ok => {
			let session_id = globals.sessions.create_session(form.username);
			cookies.add(
				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
					.expires(OffsetDateTime::from(SystemTime::now().add(globals.sessions.max_session_duration)))
					// .secure(true)	TODO Re-implement!
					.finish()
			);
			make_response!(Ok, "Authentication Successful")
		}

		LoginResult::BadCredentialChallenge => make_response!(Status::Unauthorized, "The given password is incorrect"),
		LoginResult::NonexistentUser => make_response!(Status::Unauthorized, "The given username does not exist"),
		LoginResult::LockedOut => make_response!(Status::Unauthorized, "You have failed to login too many times"),
		// LoginResult::UnexpectedCredentials => make_response!(Status::BadRequest, "The user does not support password authentication"),
	}
}


// /// Try to start a session with a username and signature
// ///
// /// If the user has already opened one and it has not expired, it will be returned
// #[rocket::get("/users_with_key?<username>&<message>&<signature>")]
// pub(crate) async fn get_session_with_key(username: String, message: String, signature: String, cookies: &CookieJar<'_>, globals: &GlobalState) -> Response {
// 	let signature = match signature.parse() {
// 		Ok(x) => x,
// 		Err(_) => return make_response!(BadRequest, "Invalid signature")
// 	};
// 	match globals.logins.try_login_key(&username, message, signature) {
// 		LoginResult::Ok => {
// 			let session_id = globals.sessions.create_session(username);
// 			cookies.add(
// 				Cookie::build(SESSION_COOKIE_NAME, session_id.to_string())
// 					.expires(OffsetDateTime::from(SystemTime::now().add(globals.sessions.max_session_duration)))
// 					.secure(true)
// 					.finish()
// 			);
// 			make_response!(Ok, "Authentication Successful")
// 		}
// 		LoginResult::BadCredentialChallenge => make_response!(Status::Unauthorized, "The given signature is incorrect"),
// 		LoginResult::NonexistentUser => make_response!(Status::Unauthorized, "The given username does not exist"),
// 		LoginResult::LockedOut => make_response!(Status::Unauthorized, "You have failed to login too many times"),
// 		LoginResult::UsedChallenge => make_response!(Status::Unauthorized, "The given challenge has been used before"),
// 		LoginResult::UnexpectedCredentials => make_response!(Status::BadRequest, "The user does not support key based authentication")
// 	}
// }


/// Tries to create a new user, granted the creating user has appropriate abilities
#[rocket::post("/sign_up", data = "<form>")]
pub(crate) async fn make_user(form: Form<UserForm>, _cookies: &CookieJar<'_>, globals: &AuthState) -> Response {
	let form = form.into_inner();

	let promise = match globals.logins.add_user(form.username, form.password) {
		Ok(x) => x,
		Err(e) => return match e {
			UserCreationError::ArgonError(e) => {
				default_error!(e, "generating password hash");
				make_response!(BUG)
			},
			UserCreationError::PasswordHasWhitespace => make_response!(BadRequest, "Password must not contain whitespace"),
			UserCreationError::UsernameInUse => make_response!(BadRequest, "Username already in use"),
			UserCreationError::BadPassword => make_response!(BadRequest, "Password is not strong enough"),
			UserCreationError::BadUsername => make_response!(BadRequest, "Username is not alphanumeric or too short or too long")
		}
	};

	promise.finalize();

	make_response!(Ok, "Sign up successful")
}

/// Tries to delete the user that is currently logged in
#[rocket::post("/delete_my_account")]
pub(crate) async fn delete_user(cookies: &CookieJar<'_>, globals: &AuthState) -> Response {
	let session_id = match check_session_id!(globals.sessions, cookies) {
		Some(x) => x,
		None => missing_session!()
	};

	let username = match globals.sessions.get_session_owner(&session_id) {
		Some(username) => username,
		None => {
			error!("Session-ID was valid but not associated with a user!");
			return make_response!(BUG)
		}
	};

	let promise = match globals.logins.delete_user(username.clone()) {
		Some(x) => x,
		None => return make_response!(BadRequest, "User does not exist")
	};

	promise.finalize();
	make_response!(Ok, "User deleted successfully")
}