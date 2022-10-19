extern crate rocket;

use std::fs::{DirBuilder, File};
use std::path::{Path, PathBuf};
use tokio::select;
use rocket::fairing::AdHoc;
use rocket::serde::Deserialize;
use mangle_rust_utils::{unwrap_result_or_default_error, default_error, bad_exit};
use simple_logger::{declare_logger, define_error, define_info, define_warn};
use simple_logger::formatters::default_format;
use rocket_async_compression::Compression;
use std::io::Write;
use rocket::State;
use tokio::io::AsyncReadExt;

const SECURE_FOLDER_NAME: &str = "secure_private";

declare_logger!([pub] LOG);
define_error!(crate::LOG, trace, export);
define_info!(crate::LOG, export);
define_warn!(crate::LOG, export);

#[derive(Deserialize)]
#[serde(crate="rocket::serde")]
struct AppConfig {
	dev_password: String,
	log_path: String
}


#[rocket::get("/<path..>")]
fn get_normal(path: PathBuf) -> Option<File> {
	if path.starts_with(SECURE_FOLDER_NAME) {
		return None
	}

	File::open(path).ok()
}


#[rocket::get("/<path..>?<password>")]
fn get_secret(path: PathBuf, password: &str, config: &State<AppConfig>) -> Result<File, String> {
	if !path.starts_with(SECURE_FOLDER_NAME) {
		return Err("Password is not needed here".into())
	}

	if !constant_time_eq::constant_time_eq(password.as_bytes(), config.dev_password.as_bytes()) {
		return Err("Invalid password".into())
	}

	File::open(path).map_err(|e| format!("Error opening file: {}", e.to_string()))
}


#[rocket::put("/<path..>?<password>", data="<data>")]
fn put_secret(path: PathBuf, data: Vec<u8>, password: &str, config: &State<AppConfig>) -> Result<String, String> {
	if !path.starts_with(SECURE_FOLDER_NAME) {
		return Err("Cannot put in this directory".into())
	}

	if !constant_time_eq::constant_time_eq(password.as_bytes(), config.dev_password.as_bytes()) {
		return Err("Invalid password".into())
	}

	File::create(path)
		.map_err(|e| format!("Error creating file: {}", e.to_string()))?
		.write_all(data.as_slice())
		.map_err(|e| format!("Error writing to file: {}", e.to_string()))?;

	Ok("Put successful!".into())
}


#[rocket::main]
async fn main() {
    let stderr_handle = LOG.attach_stderr(default_format, vec![], true);

    let path = Path::new(SECURE_FOLDER_NAME);
    if path.exists() {
        if !path.is_dir() {
            error!("{SECURE_FOLDER_NAME} is not a directory!");
            bad_exit!();
        }
    } else {
        unwrap_result_or_default_error!(
            DirBuilder::new()
                .create(SECURE_FOLDER_NAME),
            "create secure folder: {}", SECURE_FOLDER_NAME
        );
    }

	let (ready_tx, mut ready_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

	let mut user_exited = false;

    select! {
		// server
		res = rocket::build()
			.mount("/", rocket::routes![
				get_normal,
				get_secret,
				put_secret
			])
			.attach(AdHoc::config::<AppConfig>())
			.attach(AdHoc::on_liftoff("Log", |rocket| Box::pin(async {
				let config: &AppConfig = rocket.state().unwrap();

				unwrap_result_or_default_error!(
					LOG.attach_log_file(config.log_path.as_str(), default_format, vec![], true),
					"opening the log file"
				);
				drop(ready_tx);
			})))
			.attach(Compression::fairing())
			.launch() => {
			if let Err(e) = res {
				println!();
				default_error!(e, "serving http");
			}
			println!();
		}
		// stdin
		() = async {
			let _ = ready_rx.recv().await;
			warn!("Listener started up!").wait();
			stderr_handle.pause();

			let mut stdin = tokio::io::stdin();
			let mut stdout = std::io::stdout();

			loop {
				print!(">>> ");
				stdout.flush().unwrap();

				let mut line = vec![0; 1024];
				match stdin.read(&mut line).await {
					Ok(0) => return,
					Ok(n) => line.split_off(n),
					Err(_) => continue
				};
				let line = match String::from_utf8(line) {
					Ok(x) => x,
					Err(_) => {
						println!("The given command was not valid utf8");
						continue
					}
				};

				// TODO Add more commands
				match line.trim() {
					"exit" => {
						user_exited = true;
						return
					}
					_ => {}
				}
			}
		} => {},
	}
}
