use num_bigint::BigUint;
use std::io::stdin;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use zkp_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest,
};
use zkp_chaum_pederson::ZKP;
#[tokio::main]
async fn main() {
    let mut buf = String::new();
    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("Could not connect to server");
    println!("Please provide username");
    stdin().read_line(&mut buf).unwrap();
    let username = buf.trim().to_string();
    buf.clear();

    println!("Please provide Password");
    stdin().read_line(&mut buf).unwrap();
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP {
        p: p.clone(),
        q: q.clone(),
        alpha: alpha.clone(),
        beta: beta.clone(),
    };

    let (y1, y2) = zkp.compute_pair(&password);

    let request = RegisterRequest {
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };
    let _response = client.register(request).await.expect("Could not Register");
    print!("Registered Successfully: {:?}", _response);

    println!("Please provide the password (to login):");
    stdin()
        .read_line(&mut buf)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let k = ZKP::generate_random_number_below(&q);
    let (r1, r2) = zkp.compute_pair(&k);

    let request = AuthenticationChallengeRequest {
        user: username,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    let response = client
        .create_authentication_challenge(request)
        .await
        .expect("Could not create challenge")
        .into_inner();
    print!("Challenge Created Successfully: {:?}", &response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    let s = zkp.solve(&k, &c, &password);

    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    let _response = client
        .verify_authentication(request)
        .await
        .expect("Could not verify auth")
        .into_inner();

    let session_id = _response.session_id;
    print!("Authenticated Successfully, Session ID {:?}", session_id)
}
