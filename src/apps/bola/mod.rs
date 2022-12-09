use std::str::FromStr;
use std::time::{UNIX_EPOCH};
use once_cell::sync::{Lazy};
use rand::{SeedableRng, rngs::StdRng, RngCore};
use rocket::form::prelude::ErrorKind;
use rocket::serde::json::to_string;
use rocket::{async_trait};
use rocket::form::{FromFormField, Errors, Error};
use rocket::futures::{StreamExt, SinkExt};
use rocket::http::Status;
use rocket::serde::Serialize;
use rocket_db_pools::sqlx::error::DatabaseError;
use rocket_db_pools::sqlx::sqlite::SqliteError;
use tokio_tungstenite::tungstenite::Message;
use crate::ws::{WebSocket, WsList};

use super::auth::AuthenticatedUser;
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::sqlx::{self, Row, ConnectOptions};

use super::{unwrap_result_or_log, Response, make_response};
use crate::{log::*, DATABASE_CONFIGS, BOLA_DB_NAME};

#[derive(Database)]
#[database("bola_data")]
pub struct BolaData(sqlx::SqlitePool);

const DIVISOR: u32 = 3600 * 24 * 7;
const WEEK_OFFSET: u32 = 2761;

const MAX_DIFFICULTY: u8 = 3;
pub struct Difficulty(u8);


#[async_trait]
impl<'r> FromFormField<'r> for Difficulty {
    fn from_value(field:rocket::form::ValueField<'r>) -> rocket::form::Result<'r,Self> {
        let raw_value = field.value.parse()?;

        if raw_value > MAX_DIFFICULTY || raw_value == 0 {
            return Err(Errors::from(vec![Error {
                name: Some(field.name.into()),
                value: Some(field.value.into()),
                kind: ErrorKind::OutOfRange{ start: Some(0), end: Some(MAX_DIFFICULTY as isize) },
                entity: rocket::form::prelude::Entity::Field
            }]))
        }

        Ok(Self(raw_value))
    }
}


fn get_tournament_week() -> u32 {
    (UNIX_EPOCH.elapsed().unwrap().as_secs() / DIVISOR as u64) as u32 - WEEK_OFFSET
}


#[rocket::get("/tournament")]
pub fn get_tournament() -> String {
    let week = get_tournament_week();

    format!("{{
    week: {},
    seed: {},
    since: {},
    until: {}
}}",
        week,
        StdRng::seed_from_u64(week as u64).next_u32(),
        (week + WEEK_OFFSET) * DIVISOR,
        (week + WEEK_OFFSET + 1) * DIVISOR
    )
}


#[rocket::post("/tournament?<week>")]
pub async fn win_tournament(week: u32, user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> Response {
    if week != get_tournament_week() {
        return (Status::BadRequest, "The given week is not the current week".into())
    }
    
    match sqlx::query("INSERT INTO TournamentWinners (Username, Tournament) VALUES (?, ?)")
        .bind(user.username)
        .bind(week)
        .execute(&mut *bola_data)
        .await
    {
        Ok(_) => (Status::Ok, "Win was recorded".into()),
        Err(e) => match e.as_database_error() {
            Some(e) => {
                let e: &SqliteError = e.downcast_ref();

                let string;
                let code = match e.code().unwrap() {
                    std::borrow::Cow::Borrowed(x) => x,
                    std::borrow::Cow::Owned(x) => {
                        string = x;
                        string.as_str()
                    }
                };

                match code {
                    "2067" => (Status::BadRequest, "Win is already recorded".into()),
                    _ => {
                        default_error!(
                            e,
                            "inserting into TournamentWinners"
                        );
                        (Status::InternalServerError, crate::apps::BUG_MESSAGE.into())
                    }
                }
            }
            None => {
                default_error!(
                    e,
                    "inserting into TournamentWinners"
                );
                (Status::InternalServerError, crate::apps::BUG_MESSAGE.into())
            }
        }
    }
}


async fn serialize_leaderboard() -> Option<String> {
    let bola_db_url = DATABASE_CONFIGS
        .get()
        .unwrap()
        .get(crate::BOLA_DB_NAME)
        .unwrap()
        .clone()
        .find("url")
        .unwrap()
        .into_string()
        .unwrap();
    
    let mut db = unwrap_result_or_log!(
        sqlx::sqlite::SqliteConnectOptions::from_str(format!("sqlite://{bola_db_url}").as_str())
            .unwrap()
            .connect()
            .await;
        ("connecting to {}", BOLA_DB_NAME)
        return None
    );

    let mut fetch = sqlx::query("SELECT * FROM EndlessLeaderboard")
        .fetch(&mut db);
    
    let mut entries = Vec::new();
    
    while let Some(result) = fetch.next().await {
        let row = unwrap_result_or_log!(
            result;
            ("reading row in EndlessLeaderboard")
            continue
        );

        entries.push(LeaderboardEntry {
            username: row.get_unchecked("Username"),
            difficulty: row.get_unchecked("Difficulty"),
            levels: row.get_unchecked("Levels")
        })
    }
    
    Some(to_string(&entries).unwrap())
}


#[rocket::post("/leaderboard/endless?<difficulty>&<levels>")]
pub async fn add_leaderboard_entry(difficulty: Difficulty, levels: u16, user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> Response {
    let difficulty = difficulty.0;

    match sqlx::query("INSERT INTO EndlessLeaderboard (Username, Difficulty, Levels) VALUES (?, ?, ?)")
        .bind(user.username.clone())
        .bind(difficulty)
        .bind(levels)
        .execute(&mut *bola_data)
        .await
    {
        Ok(_) => match serialize_leaderboard().await {
            Some(x) => {
                STREAMS.send_all(Message::Text(x)).await;
                make_response!(Ok, "Leaderboard entry was recorded".into())
            }
            None => {
                error!("Could not serialize leaderboard");
                make_response!(BUG)
            }
        }
        Err(e) => match e.as_database_error() {
            Some(e) => {
                let e: &SqliteError = e.downcast_ref();

                let string;
                let code = match e.code().unwrap() {
                    std::borrow::Cow::Borrowed(x) => x,
                    std::borrow::Cow::Owned(x) => {
                        string = x;
                        string.as_str()
                    }
                };

                match code {
                    "2067" => match sqlx::query("UPDATE EndlessLeaderboard SET Levels = ? WHERE Username = ? AND Difficulty = ? AND Levels < ?")
                        .bind(levels)
                        .bind(user.username.clone())
                        .bind(difficulty)
                        .bind(levels)
                        .execute(&mut *bola_data)
                        .await
                        {
                            Ok(r) => if r.rows_affected() == 0 {
                                    make_response!(Ok, "Leaderboard entry was already recorded".into())
                                } else {
                                    if r.rows_affected() > 1 {
                                        error!("Multiple rows affected bug when adding leaderboard entry");
                                        return make_response!(BUG)
                                    }
                                    STREAMS.send_all(Message::Text(to_string(
                                        &LeaderboardEntry {
                                            username: user.username,
                                            difficulty,
                                            levels
                                        }
                                    ).unwrap())).await;
                                    make_response!(Status::Ok, "Leaderboard entry was recorded".into())
                                }
                            Err(e) => {
                                default_error!(
                                    e,
                                    "inserting into TournamentWinners"
                                );
                                make_response!(BUG)
                            }
                        }
                    _ => {
                        default_error!(
                            e,
                            "inserting into TournamentWinners"
                        );
                        make_response!(BUG)
                    }
                }
            }
            None => {
                default_error!(
                    e,
                    "inserting into TournamentWinners"
                );
                make_response!(BUG)
            }
        }
    }
}


static STREAMS: Lazy<WsList> = Lazy::new(WsList::new);


#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct LeaderboardEntry {
    username: String,
    difficulty: u8,
    levels: u16
}


pub fn accept_ws_stream(mut stream: WebSocket) {
    rocket::tokio::spawn(async move {
        let data = if let Some(x) = serialize_leaderboard().await {
            x
        } else {
            let _ = stream.send(Message::Text("Internal Error".into())).await;
            return
        };

        if stream.send(Message::Text(data)).await.is_err() {
            return
        }

        STREAMS.add_ws(stream).await;
    });
}
