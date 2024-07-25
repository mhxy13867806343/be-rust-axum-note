use axum::{extract::Path, routing::get, routing::post, Router, http::StatusCode, response::{
    IntoResponse,
    Response
}, Extension};
use jsonwebtoken::{
    encode,EncodingKey,Header
};
use std::net::SocketAddr;
use webbrowser;
use std::time::{
    SystemTime,
    UNIX_EPOCH
};
use sqlx::{Executor, MySql, Pool};
use dotenv::dotenv;
use std::env;
use serde::{Deserialize, Serialize};

#[derive(Debug,Serialize,Deserialize)]
struct  Claims{
    sub:String,
    exp:u64
}
#[derive(Debug,Deserialize)]
struct  AuthPayload{
    username:String,
    password:String
}
#[derive(Debug,Serialize)]
struct  TokenResponse{
    token:String
}
//自定义响应体
#[derive(Debug, Serialize)]
struct CustomResponse {
    code: u16,
    message: String,
}

impl IntoResponse for CustomResponse{
     fn into_response(self)->Response{
         let status_code=StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body=serde_json::to_string(&self).unwrap();
         (status_code,body).into_response()
     }
}


async  fn get_foo() -> &'static str {
    "Hello, World! axum"
}

async fn get_foo_age_string(Path(age):Path<i32>)->impl  IntoResponse{
    let response = if age >= 80 {
        "找阿姨"
    } else if age >= 50 {
        "找富婆去吧"
    } else if age >= 30 {
        "快去找女人吧"
    } else if age >= 18 {
        "快去找工作吧"
    } else {
        "快去嫖娼吧"
    };

    response.to_string()
}
async fn post_foo()->String{
    String::from("Hello, World! axum")
}
#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = Pool::<MySql>::connect(&database_url).await.expect("Failed to connect to the database");

    // 手动创建用户表
    create_db_table(&pool).await.expect("Failed to create users table");

    let app = Router::new().route("/", get(get_foo)).layer(Extension(pool))
        .route("/age/:age", get(get_foo_age_string))
        .route("/post_foo", post(post_foo))
        ;
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // 打开默认浏览器访问地址
    webbrowser::open("http://127.0.0.1:3000").unwrap();

    axum::Server::bind(&addr).serve(app.into_make_service()).await.unwrap();
}


fn generate_token(username:String,password:String)->Result<String,CustomResponse>{
    if username.is_empty() || password.is_empty(){
        return Err(
            CustomResponse{
                code:500,
                message:"用户名或密码不能为空".to_string()
            }
        );
    }
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    Ok(encode(
        &Header::default(),
        &Claims{
            sub:username,
            exp:now+60*60
        },
        &EncodingKey::from_secret(password.as_bytes())
    ).unwrap())
}



async fn create_user_db(pool: &Pool<MySql>) -> Result<(), sqlx::Error>{
    // 检查表是否存在
    let table_exists: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name = 'users'
        "#
    )
        .fetch_one(pool)
        .await?;

    // 如果表不存在，则创建它
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
        ).await?;
    };
    Ok(())
}
async fn create_note_db(pool: &Pool<MySql>) -> Result<(), sqlx::Error>{
    // 检查笔记表是否存在
    let notes_table_exists: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*)
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name = 'notes'
        "#
    )
        .fetch_one(pool)
        .await?;

    // 如果笔记表不存在，则创建它
    if notes_table_exists.0 == 0 {
        pool.execute(
            r#"
            CREATE TABLE notes (
                id INT AUTO_INCREMENT PRIMARY KEY,
               title VARCHAR(30) NOT NULL,
                content VARCHAR(500) NOT NULL,
                is_del INT NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
            "#
        ).await?;
    }

    Ok(())
}

async fn create_db_table(pool: &Pool<MySql>) -> Result<(), sqlx::Error> {
    // 检查表是否存在
    create_user_db(pool).await?;
    create_note_db(pool).await?;
    Ok(())
}