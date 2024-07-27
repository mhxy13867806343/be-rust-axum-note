use axum::{
    extract::{Json, Extension,State},
    routing::post,
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    BoxError,
    handler::Handler,
};
use chrono::NaiveDateTime;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{MySql, Pool, FromRow, Executor};
use dotenv::dotenv;
use std::env;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use axum::handler::HandlerWithoutStateExt;
use axum::routing::get;
use bcrypt::{hash, DEFAULT_COST};
use bcrypt::verify;
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct RegisterPayload {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    token: String,
    data: UserData,
}

#[derive(Debug, Serialize)]
struct UserData {
    username: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
struct CustomResponse {
    code: u16,
    message: String,
    data: serde_json::Value,
}

impl IntoResponse for CustomResponse {
    fn into_response(self) -> Response {
        let status_code = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::to_string(&self).unwrap();
        (status_code, body).into_response()
    }
}

#[derive(Debug, FromRow)]
struct User {
    id: i32,
    username: String,
    password: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}
impl User {
    async fn find_by_username(pool: &Pool<MySql>, username: &str) -> Result<Option<Self>, CustomResponse> {
        sqlx::query_as::<_, User>(r#"
            SELECT id, username, password, created_at, updated_at
            FROM users WHERE username = ?
        "#)
            .bind(username)
            .fetch_optional(pool)
            .await
            .map_err(|e| CustomResponse {
                code: 500,
                message: format!("数据库查询失败: {}", e),
                data: json!({}),
            })
    }

    async fn create(pool: &Pool<MySql>, username: &str, password: &str) -> Result<(), CustomResponse> {
        let hashed_password = hash(password, DEFAULT_COST).map_err(|_| CustomResponse {
            code: 500,
            message: "密码加密失败".to_string(),
            data: json!({}),
        })?;

        sqlx::query("INSERT INTO users (username, password) VALUES (?, ?)")
            .bind(username)
            .bind(hashed_password)
            .execute(pool)
            .await
            .map_err(|_| CustomResponse {
                code: 500,
                message: "创建用户失败".to_string(),
                data: json!({}),
            })?;
        Ok(())
    }
}
async  fn get_foo() -> &'static str {
    "Hello, World! 这是一个简单的网页代码而已"
}
async fn user_register_handler(
    State(pool): State<Pool<MySql>>,
    Json(payload): Json<RegisterPayload>,
) -> impl IntoResponse {
    if payload.username.is_empty() || payload.password.is_empty() {
        return CustomResponse {
            code: 400,
            message: "用户名或者密码不能为空".to_string(),
            data: json!({}),
        }
            .into_response();
    }

    match User::find_by_username(&pool, &payload.username).await {
        Ok(Some(_)) => CustomResponse {
            code: 400,
            message: "用户名已存在".to_string(),
            data: json!({}),
        }
            .into_response(),
        Ok(None) => match User::create(&pool, &payload.username, &payload.password).await {
            Ok(_) => CustomResponse {
                code: 200,
                message: "用户注册成功".to_string(),
                data: json!({}),
            }
                .into_response(),
            Err(err) => err.into_response(),
        },
        Err(err) => err.into_response(),
    }
}

async fn user_login_handler(
    State(pool): State<Pool<MySql>>,
    Json(payload): Json<AuthPayload>,
) -> impl IntoResponse {
    match generate_token(&payload.username, &payload.password, &pool).await {
        Ok(token_response) => (
            StatusCode::OK,
            Json(token_response),
        ).into_response(),
        Err(custom_response) => custom_response.into_response(),
    }
}


async fn generate_token(
    username: &str,
    password: &str,
    pool: &Pool<MySql>,
) -> Result<TokenResponse, CustomResponse> {
    if username.is_empty() || password.is_empty() {
        return Err(CustomResponse {
            code: 400,
            message: "用户名或者密码不能为空".to_string(),
            data: json!({}),
        });
    }

    match User::find_by_username(pool, username).await {
        Ok(Some(user)) => {

            if verify(password, &user.password).unwrap_or(false) {
                let expiration = (SystemTime::now() + Duration::from_secs(30 * 24 * 60 * 60))
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as usize;

                let claims = Claims {
                    sub: user.username.clone(),
                    exp: expiration,
                };

                let secret_key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
                let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret_key.as_ref()))
                    .map_err(|_| CustomResponse {
                        code: 500,
                        message: "生成token令牌失败".to_string(),
                        data: json!({}),
                    })?;

                let user_data = UserData {
                    username: user.username,
                    created_at: user.created_at.to_string(),
                    updated_at: user.updated_at.to_string(),
                };

                Ok(TokenResponse {
                    token,
                    data: user_data,
                })
            } else {
                Err(CustomResponse {
                    code: 401,
                    message: "用户名或密码无效".to_string(),
                    data: json!({}),
                })
            }
        },
        Ok(None) => Err(CustomResponse {
            code: 404,
            message: "用户名不存在".to_string(),
            data: json!({}),
        }),
        Err(err) => Err(err),
    }
}


async fn create_user_db(pool: &Pool<MySql>) -> Result<(), CustomResponse> {
    let table_exists: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name = 'users'
        "#
    )
        .fetch_one(pool)
        .await
        .map_err(|_| CustomResponse {
            code: 500,
            message: "数据库查询错误".to_string(),
            data: json!({}),
        })?;

    if table_exists.0 == 0 {
        pool.execute(
            r#"
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                password VARCHAR(255) NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            "#
        )
            .await
            .map_err(|_| CustomResponse {
                code: 500,
                message: "无法创建表".to_string(),
                data: json!({}),
            })?;
    }

    Ok(())
}

async fn create_note_db(pool: &Pool<MySql>) -> Result<(), CustomResponse> {
    let notes_table_exists: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name = 'notes'
        "#
    )
        .fetch_one(pool)
        .await
        .map_err(|_| CustomResponse {
            code: 500,
            message: "数据库查询错误".to_string(),
            data: json!({}),
        })?;

    if notes_table_exists.0 == 0 {
        pool.execute(
            r#"
            CREATE TABLE notes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(30) NOT NULL,
                content VARCHAR(500) NOT NULL,
                is_del INT NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            "#
        )
            .await
            .map_err(|_| CustomResponse {
                code: 500,
                message: "创建表失败".to_string(),
                data: json!({}),
            })?;
    }

    Ok(())
}

async fn create_db_table(pool: &Pool<MySql>) -> Result<(), CustomResponse> {
    create_user_db(pool).await?;
    create_note_db(pool).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("必须设置DATABASE_URL");
    let pool = Pool::<MySql>::connect(&database_url).await.expect("无法连接到数据库");

    create_db_table(&pool).await.expect("无法创建表");

    let app = Router::new().route("/", get(get_foo)).layer(Extension(pool.clone()))
        .route("/register", post(user_register_handler))
        .route("/login", post(user_login_handler))
        .with_state(pool);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Listening on http://{}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}