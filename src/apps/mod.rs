use rocket::http::Status;
use rocket::State;

pub mod auth;
pub mod blog;
pub mod bola;

const BUG_MESSAGE: &str = "We encountered a bug on our end. Please try again later";

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
		make_response!(NotFound, $crate::apps::BUG_MESSAGE.to_string())
	};
	(BUG, either) => {
		make_response!(NotFound, rocket::Either::Left($crate::methods::BUG_MESSAGE))
	};
    ($code: expr, $reason: expr) => {
		($code, $reason)
	};
}

use make_response;

type Response = (Status, String);


macro_rules! unwrap_result_or_log {
	(
		$res: expr;
		($($arg: tt)+)
	) => {
		unwrap_result_or_log!(
			$res;
			($($arg)+)
			return None;
		)
	};
	(
		$res: expr;
		($($arg: tt)+)
		$($on_err: tt)+
	) => {
		match $res {
			Ok(x) => x,
			Err(e) => {
				default_error!(
					e,
					$($arg)+
				);
				$($on_err)+
			}
		}
	};
}

use unwrap_result_or_log;


macro_rules! unwrap_option_or_log {
	(
		$res: expr;
		($($arg: tt)+)
	) => {
		unwrap_option_or_log!(
			$res;
			($($arg)+)
			return None;
		)
	};
	(
		$res: expr;
		($($arg: tt)+)
		$($on_err: tt)+
	) => {
		match $res {
			Some(x) => x,
			None => {
				error!($($arg)*);
				$($on_err)*
			}
		}
	};
}

use unwrap_option_or_log;
