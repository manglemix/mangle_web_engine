use std::sync::Arc;

use rocket::http::Status;
use rocket::State;

use crate::singletons::{Logins, Sessions};

pub(super) mod auth;
// pub(super) mod getters;
// pub(super) mod setters;


const BUG_MESSAGE: &str = "We encountered a bug on our end. Please try again later";
const SESSION_COOKIE_NAME: &str = "Session-ID";

use super::*;

macro_rules! make_response {
	(ServerError, $reason: expr) => {
		make_response!(rocket::http::Status::InternalServerError, $reason)
	};
	(NotFound, $reason: expr) => {
		make_response!(rocket::http::Status::NotFound, $reason)
	};
	(BadRequest, $reason: expr) => {
		make_response!(rocket::http::Status::BadRequest, $reason)
	};
	(Ok, $reason: expr) => {
		make_response!(rocket::http::Status::Ok, $reason)
	};
	(BUG) => {
		make_response!(NotFound, $crate::methods::BUG_MESSAGE)
	};
	(BUG, either) => {
		make_response!(NotFound, rocket::Either::Left($crate::methods::BUG_MESSAGE))
	};
    ($code: expr, $reason: expr) => {
		($code, $reason)
	};
}
macro_rules! check_session_id {
    ($session: expr, $cookies: expr) => {
		check_session_id!($session, $cookies, "The Session-ID is malformed", "The Session-ID is invalid or expired")
	};
    ($session: expr, $cookies: expr, either) => {
		check_session_id!($session, $cookies, rocket::Either::Left("The Session-ID is malformed"), rocket::Either::Left("The Session-ID is invalid or expired"))
	};
    ($session: expr, $cookies: expr, $err_msg1: expr, $err_msg2: expr) => {
		if let Some(cookie) = $cookies.get(SESSION_COOKIE_NAME) {
			let session_id = match $crate::singletons::SessionID::try_from(cookie.value().to_string()) {
				Ok(x) => x,
				Err(_) => return make_response!(BadRequest, $err_msg1)
			};
			if !$session.is_valid_session(&session_id) {
				return make_response!(rocket::http::Status::Unauthorized, $err_msg2)
			}
			Some(session_id)
		} else {
			None
		}
	};
}
macro_rules! missing_session {
    () => {
		return make_response!(BadRequest, "Missing Session-ID cookie")
	};
    (either) => {
		return make_response!(BadRequest, rocket::Either::Left("Missing Session-ID cookie"))
	};
}

use check_session_id;
use make_response;
use missing_session;

type Response = (Status, &'static str);


pub(super) struct _AuthState {
	pub(super) logins: Arc<Logins>,
	pub(super) sessions: Arc<Sessions>,
}


type AuthState = State<_AuthState>;