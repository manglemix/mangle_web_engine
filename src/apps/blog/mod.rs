// use std::lazy::SyncOnceCell;
use once_cell::sync::OnceCell;

use regex::Regex;
use rocket::{serde::{json::{Json}, Serialize, Deserialize}, tokio::fs::{read_dir, read_to_string}};
use crate::log::*;
use mangle_rust_utils::default_error;

use super::{unwrap_result_or_log, unwrap_option_or_log};

const BLOGS_PATH: &str = "blogs";


static DATE_REGEX: OnceCell<Regex> = OnceCell::new();


#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Blog {
    id: String,
    title: String,
    date: Option<String>,
    body: String
}


#[rocket::get("/blogs?<count>")]
pub async fn get_blogs(mut count: u8) -> Option<Json<Vec<Blog>>> {
    let date_regex = DATE_REGEX.get_or_init(|| Regex::new("^[dD]ate:").unwrap());

    let mut entries = unwrap_result_or_log!(
        read_dir(BLOGS_PATH).await;
        ("list entries in blogs")
    );

    let mut out = Vec::new();

    loop {
        let opt = unwrap_result_or_log!(
            entries.next_entry().await;
            ("trying to read blogs dir")
        );

        if let Some(entry) = opt {
            let data = unwrap_result_or_log!(
                read_to_string(entry.path()).await;
                ("trying to read entry: {:?}", entry.path())
            );

            // non-empty lines
            let mut lines = data.split('\n').filter(|line| !line.is_empty());

            let id = unwrap_option_or_log!(
                lines.next();
                ("{:?} is empty", entry.path())
            ).to_string();

            let title = unwrap_option_or_log!(
                lines.next();
                ("missing title in blog: {:?}", entry.path())
                continue
            ).trim().to_string();


            let line = unwrap_option_or_log!(
                lines.next();
                ("missing body or date in: {:?}", entry.path())
                continue
            ).trim();

            let date = if let Some(matched) = date_regex.find(line) {
                Some(
                        // get date after prefix
                    line.split_at(matched.end()).1
                        .trim()
                        .to_string()
                )
            } else {
                None
            };

            let body = if date.is_some() {
                lines
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                [line]
                .into_iter()
                    .chain(lines)
                    .collect::<Vec<_>>()
                    .join("\n")
            };

            out.push(Blog {
                id,
                title,
                date,
                body
            });

            count -= 1;
            if count == 0 {
                break
            }
        } else { break }
    }

    out.sort_by(|a, b| {
        b.id.cmp(&a.id)
    });

    Some(Json(out))
}