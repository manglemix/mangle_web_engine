#![feature(proc_macro_hygiene, decl_macro)]
#![feature(option_result_contains)]
// #![feature(once_cell)]

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use std::fs::read_to_string;
use std::time::Duration;

use once_cell::sync::OnceCell;
use rocket::http::Status;
use rocket::{catchers};
use rocket::shield::{Hsts, Shield, XssFilter, Referrer};

use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use rocket_cors::CorsOptions;
use simple_logger::formatters::default_format;

use apps::auth::{get_session_with_password, make_user, remove_session};
use mangle_detached_console::{ConsoleServer, send_message, ConsoleSendError};
use clap::Command;

use rocket_db_pools::Database;

mod apps;
mod ws;
// mod webrtc;

mod log {
	use simple_logger::prelude::*;

	pub static LOG: Logger = Logger::new();
	define_error!(crate::log::LOG, trace, export);
	define_info!(crate::log::LOG, export);
	define_warn!(crate::log::LOG, export);

	pub use {error, info};
}


use log::LOG;
use tokio_tungstenite::tungstenite::http::{Response, StatusCode};

use crate::ws::WsServer;

const BOLA_DB_NAME: &str = "bola_data";

static DATABASE_CONFIGS: OnceCell<std::collections::BTreeMap<String, rocket::figment::value::Value>> = OnceCell::new();


#[derive(Deserialize, Clone)]
#[serde(crate = "rocket::serde")]
struct AppConfig {
	log_path: String,
	max_session_duration: u32,
	login_timeout: u32,
	max_fails: u8,
	salt_len: u8,
	min_username_len: u8,
	max_username_len: u8,
	password_regex: String,
	failed_logins_path: String,
	cleanup_interval: u32,
	password_hash_length: u8,
	ws_port: u16,
	ws_ping_interval: u32
}


#[rocket::catch(default)]
fn default_catcher(status: Status, request: &rocket::Request) -> String {
	let pre_written_body = request.local_cache(String::new);
	
	if !pre_written_body.is_empty() {
		return pre_written_body.clone()
	}

	if status == Status::NotFound {
		"Not found. Usually a syntax issue".into()
	} else if status == Status::Forbidden {
		"The request performed is forbidden".into()
	} else if status == Status::InternalServerError {
		apps::BUG_MESSAGE.into()
	} else if status == Status::Unauthorized {
		"Client needs to reauthenticate".into()
	} else if status == Status::BadRequest {
		"There was an issue in the request".into()
	} else {
		format!("Error code: {status}")
	}
}

#[rocket::main]
async fn main() {
	let pipe_addr = match std::env::var_os("MANGLE_WEB_PIPE_NAME") {
		Some(x) => x,
		None => "mangle_web_engine".into()
	};

	let app = Command::new("MangleAPIEngine")
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

	match matches.subcommand() {
        Some(("start", _)) => match send_message(pipe_addr.as_os_str(), args.get(0).unwrap().to_string() + " status").await {
			Ok(msg) => {
				eprintln!("A server has already started up. Retrieved their status:\n{msg}");
				bad_exit!()
			}
			Err(e) => match e {
				ConsoleSendError::NotFound => {
					// Do nothing and move on, there is no server
				}
				e => {
					eprintln!(
						"Faced the following error while trying to check if a server has already started up:\n{e:?}"
					);
					bad_exit!()
				}
			}
		}

		None => {
			eprintln!("You need to type a command as an argument! Use -h for more information");
			bad_exit!()
		}

		_ => {
			// All subcommands not caught by the match should be sent to the server
			match send_message(pipe_addr.as_os_str(), args.join(" ")).await {
				Ok(msg) => println!("{msg}"),
				Err(e) => match e {
					ConsoleSendError::NotFound => eprintln!("Could not issue command. The server may not be running"),
					ConsoleSendError::PermissionDenied => eprintln!("Could not issue command. You may not have adequate permissions"),
					_ => eprintln!("Faced the following error while trying to issue the command: {e:?}")
				}
			}
			return
		}
    }
	
	LOG.attach_stderr(default_format, true);

	let built = rocket::build()
		.mount("/api", rocket::routes![
			get_session_with_password,
			make_user,
			remove_session,
			apps::blog::get_blogs,
			// delete_user,
		])
		.mount("/api/bola", rocket::routes![
			apps::bola::get_tournament,
			apps::bola::win_tournament,
			apps::bola::add_leaderboard_entry
		])
		.register("/", catchers![default_catcher])
		.attach(AdHoc::config::<AppConfig>())
		.attach(rocket_async_compression::Compression::fairing())
		.attach(AdHoc::on_ignite("Attach logger", |rocket| async {
			let config = rocket.state::<AppConfig>().expect(
				"There was an error in the configuration file"
			);

			unwrap_result_or_default_error!(
				apps::auth::FAILED_LOGINS
					.attach_log_file(config.failed_logins_path.as_str(), default_format, true),
				"opening the failed logins file"
			);

			unwrap_result_or_default_error!(
				LOG.attach_log_file(config.log_path.as_str(), default_format, true),
				"opening the log file"
			);

			rocket
		}))
		.attach(AdHoc::on_ignite("Build Auth State", |rocket| async {
			let state = apps::auth::make_auth_state(rocket.state::<AppConfig>().unwrap());
			rocket.manage(state)
		}))
		.attach(apps::bola::BolaData::init())
		.attach(apps::auth::Credentials::init())
		.attach(Shield::default()
			.enable(Hsts::default())
			.enable(XssFilter::default())
			.enable(Referrer::default())
		)
		.attach(unwrap_result_or_default_error!(
			{
				unwrap_result_or_default_error!(
					rocket::serde::json::from_str::<CorsOptions>(
						unwrap_result_or_default_error!(
							read_to_string("cors.json"),
							"reading cors.json"
						).as_str()
					),
					"deserializing cors.json"
				)
			}.to_cors(),
			"setting up CORS"
		))
		.attach(AdHoc::on_liftoff("Log On Liftoff", |_| Box::pin(async {
			warn!("Server started successfully");
		})));

	let ignited = unwrap_result_or_default_error!(
		built.ignite().await,
		"igniting rocket"
	);

	let db_config = unwrap_option_or_msg!(
		unwrap_result_or_default_error!(
			ignited
				.figment()
				.find_value("databases"),
			"reading database config from config file"
		).into_dict(),
		"No database path in config"
	);
	
	if !db_config.contains_key("bola_data") {
		error!("bola_data database path not found in config");
		bad_exit!()
	}
	
	if !db_config.contains_key("credentials") {
		error!("credentials database path not found in config");
		bad_exit!()
	}

	let _ = DATABASE_CONFIGS.set(db_config);

	let app_config = ignited.state::<AppConfig>().unwrap();

	ws::PING_INTERVAL.set(Duration::from_secs(app_config.ws_ping_interval as u64))
		.expect("Could not set PING_INTERVAL");

	let ws_server = unwrap_result_or_default_error!(
		WsServer::bind(
			app_config.ws_port,
			|req, response| {
				match req.uri().path() {
					"/ws/bola/leaderboards" => Ok((response, apps::bola::accept_leaderboard_ws)),
					_ => {
						let mut response = Response::new(Some("No WS endpoint at the given uri".into()));
						*response.status_mut() = StatusCode::NOT_FOUND;
						return Err(response)
					}
				}
			}
		).await,
		"starting Bola Websocket server"
	);

	let mut console_server = unwrap_result_or_default_error!(
		ConsoleServer::bind(pipe_addr.as_os_str()),
		"starting console server"
	);
	
	let mut final_event = None;

	rocket::tokio::select! {
		res = ignited.launch() => {
			if let Err(e) = res {
				default_error!(e, "serving http");
				bad_exit!();
			}
		}
		() = async {
			loop {
				let mut event = match console_server.accept().await {
					Ok(x) => x,
					Err(e) => {
						default_error!(
							e,
							"receiving console event"
						);
						continue
					}
				};
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
					}
					(cmd, _) => {
						error!("Received the following command from client console: {cmd}");
					}
				}
			}
		} => {}
		_ = ws_server.start() => {}
	};

	if let Some(mut event) = final_event {
		unwrap_result_or_default_error!(
			event.write_all("Server stopped successfully").await,
			"writing to final event"
		);
	}

	warn!("Exit Successful");
}
