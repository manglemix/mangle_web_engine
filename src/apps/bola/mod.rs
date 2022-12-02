use std::str::FromStr;
use std::sync::{Mutex};
use std::time::{UNIX_EPOCH};
use once_cell::sync::OnceCell;
use rand::{SeedableRng, rngs::StdRng, RngCore};
use rocket::futures::{StreamExt, SinkExt};
use rocket::http::Status;
use rocket::serde::Serialize;
use tokio_tungstenite::tungstenite::Message;
use crate::ws::WebSocket;

use super::auth::AuthenticatedUser;
use rocket_db_pools::{Database, Connection};
use rocket_db_pools::sqlx::{self, Row, ConnectOptions};

use super::{unwrap_result_or_log};
use crate::{log::*, DATABASE_CONFIGS, BOLA_DB_NAME};

#[derive(Database)]
#[database("bola_data")]
pub struct BolaData(sqlx::SqlitePool);

const DIVISOR: u32 = 3600 * 24 * 7;
const WEEK_OFFSET: u32 = 2761;


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
pub async fn win_tournament(week: u32, user: AuthenticatedUser, mut bola_data: Connection<BolaData>) -> (Status, ()) {
    if week != get_tournament_week() {
        return (Status::BadRequest, ())
    }
    
    match sqlx::query("INSERT INTO TournamentWinners (Username, Tournament) VALUES (?, ?)")
        .bind(user.username)
        .bind(week)
        .execute(&mut *bola_data)
        .await
    {
        Ok(_) => (Status::Ok, ()),
        Err(e) => {
            default_error!(
                e,
                "inserting into TournamentWinners"
            );
            (Status::InternalServerError, ())
        }
    }
}


static STREAMS: OnceCell<Mutex<Vec<WebSocket>>> = OnceCell::new();


#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct LeaderboardEntry {
    username: String,
    difficulty: u8,
    levels: u8
}


pub fn accept_ws_stream(mut stream: WebSocket) {
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

    rocket::tokio::spawn(async move {
        let mut db = unwrap_result_or_log!(
            sqlx::sqlite::SqliteConnectOptions::from_str(format!("sqlite://{bola_db_url}").as_str())
                .unwrap()
                .connect()
                .await;
            ("connecting to {}", BOLA_DB_NAME)
            return
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
        
        let data = rocket::serde::json::to_string(&entries).unwrap();

        if stream.send(Message::Text(data)).await.is_err() {
            return
        }

        let streams = STREAMS.get_or_init(Default::default);
        streams.lock().unwrap().push(stream);
    });
}
