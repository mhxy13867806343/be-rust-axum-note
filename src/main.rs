use axum::{extract::{Json, Extension, State}, routing::post, Router, http::StatusCode, http::HeaderMap, response::{IntoResponse, Response}, BoxError, handler::Handler, headers::{
    authorization::{
        Bearer, Authorization
    }
}, TypedHeader};
use axum::http::header::{AUTHORIZATION, FROM, HeaderValue};
use chrono::NaiveDateTime;
use jsonwebtoken::{decode, DecodingKey, Validation, errors::ErrorKind, encode, EncodingKey, Header, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{MySql, Pool, FromRow, Executor, MySqlPool};
use dotenv::dotenv;
use std::env;
use std::net::SocketAddr;
use std::process::id;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use axum::extract::{Path, Query};
use axum::handler::HandlerWithoutStateExt;
use axum::routing::{delete, get, on};
use bcrypt::{hash, DEFAULT_COST};
use bcrypt::verify;
use tokio::count;
use tower_http::cors::{CorsLayer, Any};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}
// 定义查询参数结构体
#[derive(Deserialize)]
struct PaginationParams {
    page: i32,
    pageSize: i32,
}
#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: String, // 使用 `sub` 来存储用户ID
    exp: usize,
}
#[derive(Serialize)]
struct ErrorResponse {
    code: u16,
    message: String,
    details: String,
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
    data: UserData,
    code: u16,
}

#[derive(Debug, Serialize)]
struct UserData {
    username: String,
    created_at: String,
    updated_at: String,
    token: String,
}

#[derive(Debug, Serialize)]
struct CustomResponse {
    code: u16,
    message: String,
    data: serde_json::Value,
}
// 定义 NotePayload 结构体
#[derive(Deserialize)]
struct NotePayload {
    title: String,
    content: String,
    note_id: Option<i32>,
    is_del: Option<i32>,
    createdAt: Option<String>,  // 允许为空的日期时间字符串
    updatedAt: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
struct UserNote {
    id: i32,
    user_id: i32,
    title: String,
    content: String,
    is_del: i32,
    createdAt: Option<String>,  // 允许为空的日期时间字符串
    updatedAt: Option<String>,
}
#[derive(Debug,Serialize, Deserialize, FromRow)]
struct UserNoteId {
    id: i32,
    user_id: i32,
    is_del: i32,
}
#[derive(Serialize, Deserialize)]
struct PaginatedNotes {
    page: i32,
    pageSize: i32,
    total: i64,
    code:i32,
    message:String,
    data: Vec<UserNote>,
}

#[derive(Serialize, Deserialize)]
struct detailsNotes {
    code:i32,
    message:String,
    data: serde_json::Value,
}
impl From<sqlx::Error> for CustomResponse {
    fn from(err: sqlx::Error) -> Self {
        CustomResponse {
            code: 500,
            message: format!("数据失败: {}", err),
            data: serde_json::json!({}),
        }
    }
}

//用户笔记相关
impl UserNote {
    //查询某一条记录
    // 查询某一条记录的详细信息
    async fn findDetailsNote(
        headers: HeaderMap,
        pool: MySqlPool,
        note_id: Option<i32>,  // 可选的 note_id
    ) -> Result<CustomResponse, CustomResponse> {
        // 验证 token 并获取 user_id
        let claims = Self::extract_and_validate_token(&headers).await.map_err(|e| CustomResponse {
            code: 401,
            message: "用户信息已过期或无效".to_string(),
            data: serde_json::json!({}),
        })?;
        let user_id = &claims.sub;

        // 检查 note_id 是否提供且有效
        let id = match note_id {
            Some(i) if i > 0 => i,
            _ => return Err(CustomResponse {
                code: 400,
                message: "提供的笔记 ID 无效或缺失".to_string(),
                data: serde_json::json!({}),
            }),
        };

        // 检查笔记是否存在且属于当前用户且未被删除
        let existing_note = sqlx::query_as::<_, UserNote>(
            "SELECT id, user_id, title, content, is_del,
             COALESCE(CAST(created_at AS CHAR), '') AS createdAt,
             COALESCE(CAST(updated_at AS CHAR), '') AS updatedAt
             FROM notes
             WHERE id = ? AND user_id = ? AND is_del = 0"
        )
            .bind(id)
            .bind(user_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| CustomResponse {
                code: 500,
                message: format!("查询笔记失败: {}", e),
                data: serde_json::json!({}),
            })?;

        match existing_note {
            Some(note) => Ok(CustomResponse {
                data: json!(note),
                code: 200,
                message: "获取成功".to_string(),
            }),
            None => Err(CustomResponse {
                code: 400,
                message: "未找到符合条件的笔记".to_string(),
                data: serde_json::json!({}),
            }),
        }
    }
    //查询
    async fn selectNote(
        headers: HeaderMap,
        pool: MySqlPool,
        page: i32,
        pageSize: i32,
    ) -> Result<PaginatedNotes, CustomResponse> {
        // 验证 token 并获取 user_id
        let claims = Self::extract_and_validate_token(&headers).await?;
        let user_id = &claims.sub;

        let offset = (page - 1) * pageSize;
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notes WHERE user_id = ? AND is_del = 0"
        )
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .map_err(|e| CustomResponse {
                code: 500,
                message: format!("Failed to count notes: {}", e),
                data: serde_json::json!({}),
            })?;

        let notes: Vec<UserNote> = sqlx::query_as!(
            UserNote,
            "SELECT id, user_id, title, content, is_del,
       COALESCE(CAST(created_at AS CHAR), '') AS createdAt,
       COALESCE(CAST(updated_at AS CHAR), '') AS updatedAt
FROM notes
WHERE user_id = ? AND is_del = 0
ORDER BY createdAt DESC
LIMIT ? OFFSET ?",
            user_id,
            pageSize,
            offset
        )
            .fetch_all(&pool)
            .await
            .map_err(|e| CustomResponse {
                code: 500,
                message: format!("查询失败: {}", e),
                data: serde_json::json!({}),
            })?;
        Ok(PaginatedNotes {
            page,
            pageSize,
            total,
            data: notes,
            code:200,
            message:"获取成功".to_string()
        })
    }
    //创建笔记
    async fn createNote(
        headers: HeaderMap,
        pool: MySqlPool,
        payload: NotePayload
    ) -> Result<CustomResponse, CustomResponse> {
        // 验证 token 并获取 user_id
        let claims = Self::extract_and_validate_token(&headers).await?;
        println!("claims=>{:?}",claims);
        let user_id: i32 = claims.sub.parse().map_err(|_| CustomResponse {
            code: 400,
            message: "Invalid user ID format".to_string(),
            data: serde_json::json!({}),
        })?;

        // 插入新笔记
        match sqlx::query(
            "INSERT INTO notes (user_id, title, content, is_del, created_at, updated_at)
         VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
            .bind(user_id)
            .bind(&payload.title)
            .bind(&payload.content)
            .execute(&pool)
            .await {
            Ok(_) => Ok(CustomResponse {
                code: 200,
                message: "笔记创建成功".to_string(),
                data: serde_json::json!({}),
            }),
            Err(e) => Err(CustomResponse {
                code: 500,
                message: format!("Failed to create note: {}", e),
                data: serde_json::json!({}),
            }),
        }
    }

    //更新笔记
    async fn updateNote(
        headers: HeaderMap,
        pool: MySqlPool,
        payload: NotePayload
    ) -> Result<CustomResponse, CustomResponse> {
        let claims = Self::extract_and_validate_token(&headers).await?;
        let user_id = &claims.sub;

        if let Some(id) = payload.note_id {
            let existing_note = sqlx::query_as::<_, UserNote>(
                "SELECT id, user_id, title, content, is_del,
 COALESCE(CAST(created_at AS CHAR), '') AS createdAt,
       COALESCE(CAST(updated_at AS CHAR), '') AS updatedAt
             FROM notes
             WHERE id = ? AND user_id = ? AND is_del = 0"
            )
                .bind(id)
                .bind(user_id)
                .fetch_optional(&pool)
                .await?;

            match existing_note {
                Some(_) => {
                    sqlx::query("UPDATE notes SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND is_del = 0")
                        .bind(&payload.title)
                        .bind(&payload.content)
                        .bind(id)
                        .bind(user_id)
                        .execute(&pool)
                        .await?;

                    Ok(CustomResponse {
                        code: 200,
                        message: "笔记更新成功".to_string(),
                        data: serde_json::json!({}),
                    })
                },
                None => Err(CustomResponse {
                    code: 400,
                    message: "未找到符合条件的笔记".to_string(),
                    data: serde_json::json!({}),
                })
            }
        } else {
            Err(CustomResponse {
                code: 400,
                message: "缺少必需的笔记ID".to_string(),
                data: serde_json::json!({}),
            })
        }
    }

    //删除笔记
    async fn deleteNote(
        headers: HeaderMap,
        pool: MySqlPool,
        note_id: Option<i32>  // 修改 note_id 为 Option<i32> 类型
    ) -> Result<CustomResponse, CustomResponse> {
        // 验证 token 并获取 user_id
        let claims = Self::extract_and_validate_token(&headers).await.map_err(|e| CustomResponse {
            code: 401,
            message: "用户信息已过期或无效".to_string(),
            data: serde_json::json!({}),
        })?;
        let user_id = &claims.sub;

        // 先检查 note_id 是否有值
        match note_id {
            Some(id) => {
                // 检查笔记是否存在且属于当前用户
                let note = sqlx::query_as::<_, UserNoteId>(
                    "SELECT id, user_id, is_del
                 FROM notes
                 WHERE id = ? AND user_id = ?"
                )
                    .bind(id)
                    .bind(user_id)
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| CustomResponse {
                        code: 500,
                        message: format!("查询笔记失败: {}", e),
                        data: serde_json::json!({}),
                    })?;

                match note {
                    Some(n) if n.is_del == 0 => {
                        // 笔记存在且未删除，执行删除操作
                        sqlx::query(
                            "UPDATE notes
                         SET is_del = 1, updated_at = CURRENT_TIMESTAMP
                         WHERE id = ? AND user_id = ?"
                        )
                            .bind(id)
                            .bind(user_id)
                            .execute(&pool)
                            .await
                            .map_err(|_| CustomResponse {
                                code: 500,
                                message: "笔记删除失败".to_string(),
                                data: serde_json::json!({}),
                            })?;
                        Ok(CustomResponse {
                            code: 200,
                            message: "笔记删除成功".to_string(),
                            data: serde_json::json!({}),
                        })
                    },
                    Some(n) if n.is_del == 1 => {
                        Err(CustomResponse {
                            code: 400,
                            message: "笔记已被删除".to_string(),
                            data: serde_json::json!({}),
                        })
                    },
                    None => {
                        Err(CustomResponse {
                            code: 400,
                            message: "笔记不存在".to_string(),
                            data: serde_json::json!({}),
                        })
                    },
                    _ => {
                        Err(CustomResponse {
                            code: 500,
                            message: "未预期的错误".to_string(),
                            data: serde_json::json!({}),
                        })
                    }
                }
            },
            None => {
                // note_id 为空的处理
                Err(CustomResponse {
                    code: 400,
                    message: "未提供有效的笔记ID".to_string(),
                    data: serde_json::json!({}),
                })
            }
        }
    }
    
    // 检测用户token的合法性
    async fn extract_and_validate_token(headers: &HeaderMap) -> Result<TokenClaims, CustomResponse> {
        let auth_header = headers.get("Authorization")
            .ok_or_else(|| CustomResponse {
                code: 401,
                message: "No Authorization header found".to_string(),
                data: serde_json::json!({}),
            })?;
        let auth_str = auth_header.to_str().map_err(|_| CustomResponse {
            code: 401,
            message: "Invalid Authorization header".to_string(),
            data: serde_json::json!({}),
        })?;

        let token = auth_str.trim_start_matches("Bearer ").trim();
        validate_token(token).map_err(|err| CustomResponse {
            code: 401,
            message: "用户信息已过期".to_string(),
            data: serde_json::json!({ "error": err }),
        })
    }
}
impl IntoResponse for ErrorResponse {
    fn into_response(self) -> axum::response::Response {
        // 先从 self 中提取需要的字段
        let code = self.code;
        let body = Json(self); // 移动发生在这里，但已经提取了需要的字段

        // 使用提取的字段，不再需要访问 self
        (axum::http::StatusCode::from_u16(code).unwrap(), body).into_response()
    }
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
    match create_user_token(&payload.username, &payload.password, &pool).await {
        Ok(token_response) => (
            StatusCode::OK,
            Json(token_response),
        ).into_response(),
        Err(custom_response) => custom_response.into_response(),
    }
}
//验证用户token行为
fn validate_token(token: &str) -> Result<TokenClaims, String> {
    let secret_key = std::env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    jsonwebtoken::decode::<TokenClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret_key.as_ref()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256)
    ).map(|data| data.claims)
        .map_err(|err| err.to_string())
}

//生成用户token
async fn create_user_token(
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
                    sub: user.id.to_string(),
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
                    token,
                };

                Ok(TokenResponse {
                    data: user_data,
                    code:200
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
            code: 400,
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
                message: "用户名创建失败".to_string(),
                data: json!(
                      CustomResponse{
                    code: 400,
                    message: "用户名创建失败".to_string(),
                    data: json!({}),
                }
                ),
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
async fn extract_user_id_from_token(
    auth_header: TypedHeader<Authorization<Bearer>>,
) -> Result<TokenClaims, Json<CustomResponse>> {
    let token = auth_header.0.token();
    validate_token(token)
        .map_err(|err| Json(CustomResponse {
            code: 401,
            message: "用户信息已过期或无效".to_string(),
            data: json!({ "error": err }),
        }))
}
async fn select_note_handler(
    headers: HeaderMap,
    Query(pagination): Query<PaginationParams>,
    Extension(pool): Extension<MySqlPool>
) -> Result<Json<PaginatedNotes>, Json<CustomResponse>> {
    // 从前端传递的查询参数中提取分页信息
    let page = pagination.page;
    let page_size = pagination.pageSize;

    // 调用 selectNote 方法
    match UserNote::selectNote(headers, pool, page, page_size).await {
        Ok(notes) => Ok(Json(notes)),
        Err(error) => Err(Json(error)),
    }
}

async fn create_note_handler(
    headers: HeaderMap,
    Extension(pool): Extension<MySqlPool>,
    Json(payload): Json<NotePayload>
) -> Result<Json<CustomResponse>, Json<CustomResponse>> {
    match UserNote::createNote(headers, pool, payload).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(Json(error)),
    }
}

async fn update_note_handler(
    headers: HeaderMap,
    Extension(pool): Extension<MySqlPool>,
    Json(payload): Json<NotePayload>  // 移除 Path 参数，从 JSON 中获取 note_id
) -> Result<Json<CustomResponse>, Json<CustomResponse>> {
    match UserNote::updateNote(headers, pool, payload).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(Json(error)),
    }
}


async fn delete_note_handler(
    headers: HeaderMap,
    Extension(pool): Extension<MySqlPool>,
    Path(note_id): Path<i32>
) -> Result<Json<CustomResponse>, Json<CustomResponse>> {
    match UserNote::deleteNote(headers, pool, Some(note_id)).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(Json(error)),
    }
}
async fn find_note_handler(
    headers: HeaderMap,
    Extension(pool): Extension<MySqlPool>,
    Path(note_id): Path<i32>
) -> Result<Json<CustomResponse>, Json<CustomResponse>> {
    match UserNote::findDetailsNote(headers, pool, Some(note_id)).await {
        Ok(response) => Ok(Json(response)),
        Err(error) => Err(Json(error)),
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("必须设置DATABASE_URL");
    let pool = Pool::<MySql>::connect(&database_url).await.expect("无法连接到数据库");

    create_db_table(&pool).await.expect("无法创建表");
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let app = Router::new().route("/", get(get_foo)).layer(Extension(pool.clone()))
        .route("/register", post(user_register_handler))
        .route("/login", post(user_login_handler))
        .route("/note/list", get(select_note_handler))
        .route("/note/add",post(create_note_handler))
        .route("/note/update", post(update_note_handler))
        .route("/note/delete/:{note_id}", post(delete_note_handler))
        .route("/note/find/:{note_id}", get(find_note_handler))
        .layer(cors)
        .with_state(pool.clone())
        .layer(Extension(pool.clone()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Listening on http://{}", addr);

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}