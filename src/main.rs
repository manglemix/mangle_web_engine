#![feature(proc_macro_hygiene, decl_macro)]

/// The user authentication side of mangle db
///
/// Mainly uses password authentication

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use rocket::tokio::fs::File;
use std::io::{Read, ErrorKind};
use std::path::PathBuf;
use std::time::Duration;

use rocket::fairing::AdHoc;
use rocket::http::ContentType;
use rocket::serde::Deserialize;
use regex::Regex;
use simple_logger::formatters::default_format;
use simple_logger::prelude::*;

use methods::auth::{get_session_with_password, make_user, delete_user};
use singletons::{Logins, Sessions};
use mangle_detached_console::{ConsoleServer, send_message};
use clap::{Command};

mod singletons;
mod methods;


declare_logger!([pub] LOG);
define_error!(crate::LOG, trace, export);
define_info!(crate::LOG, export);
define_warn!(crate::LOG, export);


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


#[rocket::get("/<path>")]
async fn unlocked_get(mut path: PathBuf) -> Option<(ContentType, File)> {
	if !path.exists() {
		return None
	}

	if path.is_dir() {
		path.push("index.html");
	}

	let extension = match path.extension().map(|x| x.to_str()).flatten() {
		Some(x) => x,
		None => {
			error!("Tried to access existing file with no extension: {path:?}");
			return None
		}
	};

	let content_type = match ContentType::from_extension(extension) {
		Some(x) => x,
		None => {
			error!("Tried to access existing unsupported file: {path:?}");
			return None
		}
	};
	
	Some((
		content_type,
		File::open(path).await.ok()?
	))
}


static PIPE_ADDR: &str = "mangle_web_engine";


#[rocket::main]
async fn main() {
	let app = Command::new("MangleWebEngine")
		.version(env!("CARGO_PKG_VERSION"))
		.author("manglemix")
		.about("The software behind manglemix.com")
		.subcommand(
			Command::new("start")
				.about("Starts the web server in the current directory")
		)
		.subcommand(
			Command::new("status")
				.about("Checks the status of the server")
		)
		.subcommand(
			Command::new("stop")
				.about("Stops the currently running server")
		);
	
	let args: Vec<String> = std::env::args().collect();
	let matches = app.clone().get_matches_from(args.clone());

	match matches.subcommand().unwrap() {
        ("start", _sub_matches) => {}
		_ => {
			// Still a valid match, but one that should be sent to the server
			match send_message(PIPE_ADDR, args.join(" ")).await {
				Ok(msg) => println!("{msg}"),
				Err(e) => match e.kind() {
					ErrorKind::NotFound => eprintln!("Could not issue command. The server may not be running"),
					_ => eprintln!("Faced the following error while trying to issue the command: {e:?}")
				}
			}
			return
		}
    }

	#[cfg(debug_assertions)]
	LOG.attach_stderr(default_format, vec![], true);
	#[cfg(not(debug_assertions))]
	let stderr_handle = LOG.attach_stderr(default_format, vec![], true);

	let mut data = String::new();
	{
		let mut file = unwrap_result_or_default_error!(
			std::fs::File::open("user_password_map.txt"),
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
		unlocked_get,
		get_session_with_password,
		make_user,
		delete_user
	])
	.attach(AdHoc::config::<AppConfig>())
	.attach(rocket_async_compression::Compression::fairing())
	.attach(AdHoc::on_ignite("Attach logger", |rocket| async {
		let config = rocket.state::<AppConfig>().expect(
			"There was an error in the configuration file"
		);

		unwrap_result_or_default_error!(
			singletons::FAILED_LOGINS
				.attach_log_file(config.failed_logins_path.as_str(), default_format, vec![], true),
			"opening the failed logins file"
		);

		unwrap_result_or_default_error!(
			LOG.attach_log_file(config.log_path.as_str(), default_format, vec![], true),
			"opening the log file"
		);

		rocket
	}))
	.attach(AdHoc::on_ignite("Build GlobalState", |rocket| async {
		let config = rocket.state::<AppConfig>().unwrap().clone();

		rocket.manage(methods::_GlobalState {
			logins: Logins::new(
				user_password_map,
				Duration::from_secs(config.login_timeout),
				config.max_fails,
				config.salt_len,
				config.min_username_len,
				config.max_username_len,
				config.cleanup_delay,
				unwrap_result_or_default_error!(
					Regex::new(config.password_regex.as_str()),
					"parsing password regex"
				),
			),
			sessions: Sessions::new(Duration::from_secs(config.max_session_duration), config.cleanup_delay),
		})
	}))
	.attach(AdHoc::on_liftoff("Log On Liftoff", |_| Box::pin(async {
		warn!("Server started successfully");
	})));

	let ignited = unwrap_result_or_default_error!(
		built.ignite().await,
		"igniting rocket"
	);

	let mut server = unwrap_result_or_default_error!(
		ConsoleServer::bind(PIPE_ADDR),
		"starting console server"
	);
	
	#[cfg(not(debug_assertions))]
	stderr_handle.close();
	let mut final_event = None;

	rocket::tokio::select! {
		res = ignited.launch() => {
			if let Err(e) = res {
				default_error!(e, "serving http");
			}
		}
		() = async {
			loop {
				let mut event = server.accept().await;
				let message = event.take_message();

				let matches = match app.clone().try_get_matches_from(message.split_whitespace()) {
					Ok(x) => x,
					Err(e) => {
						default_error!(
							e,
							"parsing from client console message: {message}"
						);
						continue
					}
				};

				macro_rules! write_all {
					($msg: expr) => {
						match event.write_all($msg).await {
							Ok(()) => {}
							Err(e) => {
								default_error!(
									e,
									"responding to client console"
								);
								continue
							}
						}
					}
				}

				match matches.subcommand().unwrap() {
					("status", _) => write_all!("Server is good!"),
					("stop", _) => {
						final_event = Some(event);
						warn!("Stop command issued");
						return
					},
					(cmd, _) => {
						error!("Received the following command from client console: {cmd}");
					}
				}

				
			}
		} => {},
	};

	warn!("Exit Successful");
	if let Some(mut event) = final_event {
		let _ = event.write_all("Server stopped successfully").await;
	}
}
