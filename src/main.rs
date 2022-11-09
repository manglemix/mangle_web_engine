#![feature(proc_macro_hygiene, decl_macro)]

/// The user authentication side of mangle db
///
/// Mainly uses password authentication

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use std::fs::File;
use std::io::{Error as IOError, ErrorKind, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use regex::Regex;
use simple_logger::prelude::*;

use methods::auth::{get_session_with_password, make_user, delete_user};
// use methods::getters::{borrow_resource, directory_tools};
// use methods::setters::{post_data, put_resource};
use singletons::{Credential, Logins, Sessions};

mod singletons;
// mod configs;
// mod parsing;


declare_logger!([pub] LOG);
define_error!(crate::LOG, trace, export);
define_info!(crate::LOG, export);
define_warn!(crate::LOG, export);

mod methods;


fn path_buf_to_segments(path: &PathBuf) -> Vec<String> {
	path.components().map(|x| x.as_os_str().to_str().map(|x| x.to_string())).flatten().collect()
}


#[derive(Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct AppConfig {
	log_path: String,
	max_session_duration: u64,
	login_timeout: u64,
	max_fails: u8,
	salt_len: u8,
	min_username_len: u8,
	max_username_len: u8,
	cleanup_delay: u32,
	password_regex: String,
	failed_logins_path: String,
}


#[rocket::main]
async fn main() {
	let mut data = String::new();
	{
		let mut file = unwrap_result_or_default_error!(
			File::open("user_password_map.txt"),
			"opening user_password_map.txt"
		);
	
		unwrap_result_or_default_error!(
			file.read_to_string(&mut data),
			"reading user_password_map.txt"
		);
	}

	let user_password_map = unwrap_result_or_default_error!(
		Logins::parse_user_password_map(data),
		"parsing user_password_map.txt"
	);

	let built = rocket::build()
	.mount("/", rocket::routes![
		get_session_with_password,
		make_user,
		delete_user
	])
	.attach(AdHoc::config::<AppConfig>())
	.attach(rocket_async_compression::Compression::fairing())
	.attach(AdHoc::on_ignite("Build GlobalState", |rocket| async {
		let config: &AppConfig = rocket.state().unwrap();
		let config = config.clone();

		rocket.manage(methods::_GlobalState {
			logins: Logins::new(
				user_password_map,
				Duration::from_secs(config.login_timeout),
				config.max_fails,
				config.salt_len,
				config.min_username_len,
				config.max_username_len,
				config.cleanup_delay,
				unwrap_result_or_default_error!(Regex::new(config.password_regex.as_str()), "parsing password regex"),
			),
			sessions: Sessions::new(Duration::from_secs(config.max_session_duration), config.cleanup_delay),
		})
	}));

	let ignited = unwrap_result_or_default_error!(
		built.ignite().await,
		"igniting rocket"
	);

	rocket::tokio::select! {
		res = ignited.launch() => {
			if let Err(e) = res {
				default_error!(e, "serving http");
			}
		}
		() = async {
			warn!("Listener started up!").wait();
		} => {},
	}
	;

	warn!("Exit Successful");
}
