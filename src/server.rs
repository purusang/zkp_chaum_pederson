use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};
use zkp_chaum_pederson::ZKP;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[derive(Debug, Default)]
pub struct UserInfo {
    //registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,

    //authorization
    pub r1: BigUint,
    pub r2: BigUint,

    //verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[derive(Debug, Default)]
struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>, // Mutex will be used to make the struct thread safe
    pub auth_id_to_user: Mutex<HashMap<String, String>>, // Mutex will be used to make the struct thread safe
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("Processing Register: {:?}", request);
        let request = request.into_inner();

        let user_name = request.user;

        let mut user_info = UserInfo::default();

        user_info.user_name = user_name.clone();
        user_info.y1 = BigUint::from_bytes_be(&request.y1);
        user_info.y2 = BigUint::from_bytes_be(&request.y2);

        let mut user_info_hashmap = self.user_info.lock().unwrap();
        user_info_hashmap.insert(user_name, user_info);
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        println!("Creating Authentication Challenge: {:?}", request);
        let request = request.into_inner();
        let user_name = request.user;

        let mut user_info_hashmap = self.user_info.lock().unwrap();

        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);
            let (_, _, _, q) = ZKP::get_constants();

            let c = ZKP::generate_random_number_below(&q);
            user_info.c = c.clone();
            let auth_id = ZKP::generate_random_string(12);

            let mut auth_id_to_user = &mut self.auth_id_to_user.lock().unwrap();
            auth_id_to_user.insert(auth_id.clone(), user_name);

            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id: auth_id.into(),
                c: c.to_bytes_be(),
            }))
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("User {} not found", user_name),
            ));
        }
    }
    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Verifying Authentication: {:?}", request);

        let request = request.into_inner();
        let auth_id = request.auth_id;

        let user_info_hashmap = &mut self.user_info.lock().unwrap();
        let auth_id_to_user = self.auth_id_to_user.lock().unwrap();

        if let Some(user_name) = auth_id_to_user.get(&auth_id) {
            if let Some(user_info) = user_info_hashmap.get_mut(user_name) {
                user_info.session_id = ZKP::generate_random_string(12);
                user_info.s = BigUint::from_bytes_be(&request.s);

                let (a, b, p, q) = ZKP::get_constants();
                let y1 = &user_info.y1;
                let y2 = &user_info.y2;
                let r1 = &user_info.r1;
                let r2 = &user_info.r2;
                let c = &user_info.c;
                let s = &user_info.s;

                let zkp = ZKP {
                    p: p.clone(),
                    q: q.clone(),
                    alpha: a.clone(),
                    beta: b.clone(),
                };

                let result = zkp.verify(r1, r2, y1, y2, c, s);
                if result {
                    Ok(Response::new(AuthenticationAnswerResponse {
                        session_id: user_info.session_id.clone(),
                    }))
                } else {
                    return Err(Status::new(
                        Code::InvalidArgument,
                        "Authentication failed".to_string(),
                    ));
                }
            } else {
                return Err(Status::new(
                    Code::NotFound,
                    format!("User {} not found", user_name),
                ));
            }
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("Auth ID {} not found", auth_id),
            ));
        }
    }
}
#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!(" ✔ Running the server on: {}", addr);
    let auth_impl = AuthImpl::default();
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("Invalid address"))
        .await
        .unwrap();
}
