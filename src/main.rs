#![feature(proc_macro_hygiene, decl_macro)]
#![feature(option_result_contains)]
// #![feature(once_cell)]

#[macro_use]
extern crate mangle_rust_utils;
extern crate rocket;

use rocket::http::Method;
use rocket::{catchers};
use rocket::shield::{Hsts, Shield, XssFilter, Referrer};

use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use rocket_cors::{AllowedOrigins, AllowedHeaders};
use simple_logger::formatters::default_format;

use apps::auth::{get_session_with_password, make_user, delete_user};
use mangle_detached_console::{ConsoleServer, send_message, ConsoleSendError};
use clap::Command;

mod apps;

mod log {
	use simple_logger::prelude::*;

	declare_logger!([pub] LOG);
	define_error!(crate::log::LOG, trace, export);
	define_info!(crate::log::LOG, export);
	define_warn!(crate::log::LOG, export);

	pub use {error, info};
}


use log::LOG;


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


#[rocket::catch(404)]
async fn not_found() -> String {
	"Not found".into()
}


#[rocket::catch(403)]
async fn forbidden() -> String {
	"Forbidden".into()
}


#[rocket::catch(500)]
async fn internal_error() -> String {
	"Internal Error".into()
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
	
	LOG.attach_stderr(default_format, vec![], true);

	let allowed_origins = AllowedOrigins::some_exact(&[
		"https://manglemix.com",
		#[cfg(debug_assertions)]
		"http://127.0.0.1:5173"
	]);

	let built = rocket::build()
		.mount("/api", rocket::routes![
			get_session_with_password,
			make_user,
			delete_user,
			apps::blog::get_blogs
		])
		.register("/", catchers![not_found, internal_error, forbidden])
		.attach(AdHoc::config::<AppConfig>())
		.attach(rocket_async_compression::Compression::fairing())
		.attach(AdHoc::on_ignite("Attach logger", |rocket| async {
			let config = rocket.state::<AppConfig>().expect(
				"There was an error in the configuration file"
			);

			unwrap_result_or_default_error!(
				apps::auth::FAILED_LOGINS
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
			let state = apps::auth::make_auth_state(rocket.state::<AppConfig>().unwrap());
			rocket.manage(state)
		}))
		.attach(AdHoc::on_liftoff("Log On Liftoff", |_| Box::pin(async {
			warn!("Server started successfully");
		})))
		.attach(Shield::default()
			.enable(Hsts::default())
			.enable(XssFilter::default())
			.enable(Referrer::default())
		)
		.attach(unwrap_result_or_default_error!(
			rocket_cors::CorsOptions {
				allowed_origins,
				allowed_methods: vec![Method::Get].into_iter().map(From::from).collect(),
				allowed_headers: AllowedHeaders::some(&["Authorization", "Accept"]),
				allow_credentials: true,
				..Default::default()
			}.to_cors(),
			"setting up CORS"
		));

	let ignited = unwrap_result_or_default_error!(
		built.ignite().await,
		"igniting rocket"
	);

	let mut server = unwrap_result_or_default_error!(
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
				let mut event = match server.accept().await {
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
					},
					(cmd, _) => {
						error!("Received the following command from client console: {cmd}");
					}
				}
			}
		} => {},
	};

	if let Some(mut event) = final_event {
		unwrap_result_or_default_error!(
			event.write_all("Server stopped successfully").await,
			"writing to final event"
		);
	}

	warn!("Exit Successful");
}
