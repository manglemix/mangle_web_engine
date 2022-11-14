use rocket::{serde::{json::{Json, from_str}, Serialize, Deserialize}, tokio::fs::{read_dir, read_to_string}};
use crate::log::*;
use mangle_rust_utils::default_error;

const BLOGS_PATH: &str = "blogs";


#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Blog {
    title: String,
    date: Option<String>,
    body: String
}


#[rocket::get("/api/blogs?<count>")]
pub async fn get_blogs(count: u8) -> Option<Json<Vec<Blog>>> {
    let mut entries = match read_dir(BLOGS_PATH).await {
        Ok(x) => x,
        Err(e) => {
            default_error!(
                e,
                "trying to read blogs dir"
            );
            return None
        }
    };

    let mut out = Vec::new();

    loop {
        let opt = match entries.next_entry().await {
            Ok(x) => x,
            Err(e) => {
                default_error!(
                    e,
                    "trying to read blogs dir"
                );
                return None
            }
        };

        if let Some(entry) = opt {
            let data = match read_to_string(entry.path()).await {
                Ok(x) => x,
                Err(e) => {
                    default_error!(
                        e,
                        "trying to read entry: {:?}", entry.path()
                    );
                    return None
                }
            };

            out.push(match from_str(data.as_str()) {
                Ok(x) => x,
                Err(e) => {
                    default_error!(
                        e,
                        "trying to read entry: {:?}", entry.path()
                    );
                    continue;
                }
            });
        } else { break }
    }

    Some(Json(out))
}