use std::str::FromStr;
use std::time::{UNIX_EPOCH};
use once_cell::sync::{Lazy};
use rand::{SeedableRng, rngs::StdRng, RngCore};
use rocket::form::prelude::ErrorKind;
use rocket::serde::json::to_string;
use rocket::{async_trait, FromForm};
use rocket::form::{FromFormField, Errors, Error, Form, ValueField};
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

use super::{unwrap_result_or_log, Response, make_response, unwrap_option_or_log};
use crate::{log::*, BOLA_DB_URL};

#[derive(Database)]
#[database("bola_data")]
pub struct BolaData(sqlx::SqlitePool);

const DIVISOR: u32 = 3600 * 24 * 7;
const WEEK_OFFSET: u32 = 2761;

const MAX_DIFFICULTY: u8 = 3;
/// Starts from 1 and ends at 3 inclusive
pub struct Difficulty(u8);


#[async_trait]
impl<'r> FromFormField<'r> for Difficulty {
    fn from_value(field:ValueField<'r>) -> rocket::form::Result<'r,Self> {
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

    format!("{{\"week\": {}, \"seed\": {}, \"since\": {}, \"until\": {}}}",
        week,
        StdRng::seed_from_u64(week as u64).next_u32(),
        (week + WEEK_OFFSET) * DIVISOR,
        (week + WEEK_OFFSET + 1) * DIVISOR
    )
}


pub struct WinTournamentForm {
    week: u32
}


impl<'r> FromFormField<'r> for WinTournamentForm {
    fn from_value(field:ValueField<'r>) -> rocket::form::Result<'r,Self> {
        let raw_value = field.value.parse()?;

        let current_week = get_tournament_week();
        if raw_value != current_week {
            return Err(Errors::from(vec![Error {
                name: Some(field.name.into()),
                value: Some(field.value.into()),
                kind: ErrorKind::OutOfRange{ start: Some(current_week as isize), end: Some(current_week as isize) },
                entity: rocket::form::prelude::Entity::Field
            }]))
        }

        Ok(Self{
            week: raw_value
        })
    }
}


#[rocket::post("/tournament", data = "<data>")]
pub async fn win_tournament(data: Form<WinTournamentForm>, user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> Response {
    let week = data.week;

    match sqlx::query("INSERT INTO TournamentWinners (Username, Tournament) VALUES (?, ?)")
        .bind(user.username)
        .bind(week)
        .execute(&mut *bola_data)
        .await
    {
        Ok(_) => make_response!(Ok, "Win was recorded".into()),
        Err(e) => {
            let e = unwrap_option_or_log!(
                e.as_database_error();
                ("inserting into TournamentWinners")
                return make_response!(BUG)
            );

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
                "2067" => make_response!(BadRequest, "Win is already recorded".into()),
                _ => {
                    default_error!(
                        e,
                        "inserting into TournamentWinners"
                    );
                    make_response!(BUG)
                }
            }
        }
    }
}


#[derive(Serialize, Default)]
#[serde(crate = "rocket::serde")]
struct AccountData {
    easy_max_level: u16,
    normal_max_level: u16,
    hard_max_level: u16,
    tournament_wins: u16,
    won_tournament: bool
}


#[rocket::get("/account")]
pub async fn get_account(user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> Response {
    let mut data = AccountData::default();

    {
        let mut fetch = sqlx::query("SELECT Difficulty, Levels FROM EndlessLeaderboard WHERE Username = ?")
            .bind(user.username.clone())
            .fetch(&mut *bola_data);

        while let Some(result) = fetch.next().await {
            let row = unwrap_result_or_log!(
                result;
                ("reading row in EndlessLeaderboard")
                continue
            );

            let level: u16 = row.get_unchecked("Levels");

            match row.get_unchecked::<u8, _>("Difficulty") {
                1 => data.easy_max_level = level,
                2 => data.normal_max_level  = level,
                3 => data.hard_max_level = level,
                x => {
                    error!("Unknown difficulty: {x} found while getting account data for {}", user.username);
                }
            }
        }
    }

    let row = unwrap_result_or_log!(
        sqlx::query("SELECT COUNT(*) FROM TournamentWinners WHERE Username = ?")
            .bind(user.username.clone())
            .fetch_one(&mut *bola_data)
            .await;
            ("counting tournament wins for {}", user.username)
            return make_response!(BUG)
    );

    data.tournament_wins = row.get_unchecked("COUNT(*)");

    let row = unwrap_result_or_log!(
        sqlx::query("SELECT COUNT(*) FROM TournamentWinners WHERE Username = ? AND Tournament = ?")
            .bind(user.username.clone())
            .bind(get_tournament_week())
            .fetch_one(&mut *bola_data)
            .await;
            ("counting tournament wins for {}", user.username)
            return make_response!(BUG)
    );

    let win_count: u32 = row.get_unchecked("COUNT(*)");

    if win_count > 1 {
        error!("User: {} has more than one win for this week: {}", user.username, get_tournament_week());
    }

    data.won_tournament = win_count > 0;

    make_response!(Ok, to_string(&data).unwrap())
}


#[derive(FromForm)]
pub struct LeaderboardEntryRequest {
    difficulty: Difficulty,
    levels: u16
}


#[rocket::post("/leaderboard/endless", data = "<data>")]
pub async fn add_leaderboard_entry(data: Form<LeaderboardEntryRequest>, user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> Response {
    let data = data;
    let difficulty = data.difficulty.0;
    let levels = data.levels;
    let current_time = UNIX_EPOCH.elapsed().unwrap().as_secs_f64().round();

    match sqlx::query("INSERT INTO EndlessLeaderboard (Username, Difficulty, Levels, Time) VALUES (?, ?, ?, ?)")
        .bind(user.username.clone())
        .bind(difficulty)
        .bind(levels)
        .bind(current_time)
        .execute(&mut *bola_data)
        .await
    {
        Ok(_) => {}
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
                    "2067" => match sqlx::query("UPDATE EndlessLeaderboard SET Levels = ?, Time = ? WHERE Username = ? AND Difficulty = ? AND Levels < ?")
                        .bind(data.levels)
                        .bind(current_time)
                        .bind(user.username.clone())
                        .bind(difficulty)
                        .bind(levels)
                        .execute(&mut *bola_data)
                        .await
                        {
                            Ok(r) => if r.rows_affected() == 0 {
                                    return make_response!(Ok, "Leaderboard entry was already recorded".into())
                                } else if r.rows_affected() > 1 {
                                    error!("Multiple rows affected bug when adding leaderboard entry");
                                    return make_response!(BUG)
                                }
                            Err(e) => {
                                default_error!(
                                    e,
                                    "inserting into EndlessLeaderboard"
                                );
                                return make_response!(BUG)
                            }
                        }
                    _ => {
                        default_error!(
                            e,
                            "inserting into EndlessLeaderboard"
                        );
                        return make_response!(BUG)
                    }
                }
            }
            None => {
                default_error!(
                    e,
                    "inserting into EndlessLeaderboard"
                );
                return make_response!(BUG)
            }
        }
    }

    STREAMS.send_all(Message::Text(to_string(
        &LeaderboardEntry {
            username: user.username,
            difficulty,
            levels,
            time: current_time
        }
    ).unwrap())).await;

    make_response!(Status::Ok, "Leaderboard entry was recorded".into())
}


async fn serialize_leaderboard() -> Option<String> {
    let mut db = unwrap_result_or_log!(
        sqlx::sqlite::SqliteConnectOptions::from_str(format!("sqlite://{}", BOLA_DB_URL.get().unwrap()).as_str())
            .unwrap()
            .connect()
            .await;
        ("connecting to bola_data")
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
            levels: row.get_unchecked("Levels"),
            time: row.get_unchecked("Time")
        })
    }
    
    Some(to_string(&entries).unwrap())
}


static STREAMS: Lazy<WsList> = Lazy::new(WsList::new);


#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct LeaderboardEntry {
    username: String,
    difficulty: u8,
    levels: u16,
    time: f64
}


pub fn accept_leaderboard_ws(mut stream: WebSocket) {
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
