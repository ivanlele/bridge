use candid::Nat;
use ic_cdk::api::management_canister::ecdsa::{
    sign_with_ecdsa, SignWithEcdsaArgument, EcdsaKeyId, EcdsaCurve
};
use ic_web3::types::H256;
// use generic_array::GenericArray;
use ic_cdk::api::management_canister::http_request::{
    HttpResponse, TransformArgs,
};
use ethabi::{Token, Address, Uint};
use ic_web3::transports::ICHttp;
use ic_web3::Web3;
use ic_web3::ic::get_eth_addr;
use ic_web3::signing::{hash_message, keccak256};
// use k256::ecdsa::Signature;
// use k256::elliptic_curve::scalar::IsHigh;
// use secp256k1::{Secp256k1, Message, ecdsa, PublicKey};

const KEY_NAME: &str = "dfx_test_key";
const INPURA_API_KEY: &str = "d009354476b140008dd04c741c00341b";
enum Network {
    MainNet,
    Goerli,
    Sepolia
}

impl Network {
    fn as_str(&self) -> &'static str {
        match self {
            Network::MainNet => "mainnet",
            Network::Goerli => "goerli",
            Network::Sepolia => "sepolia"
        }
    }

    fn from(raw_value: &str) -> Network {
        match raw_value {
            "mainnet" => Network::MainNet,
            "goerli" => Network::Goerli,
            "sepolia" => Network::Sepolia,
            _ => panic!("unavaible network"),
        }
    }
}

#[ic_cdk_macros::query]
fn transform(response: TransformArgs) -> HttpResponse {
    response.response
}

#[ic_cdk_macros::update]
async fn eth_address() -> String {
    hex::encode(
        get_eth_addr(None, None, KEY_NAME.to_string())
            .await
            .expect("failed to get an ethereum address")
    )
}

#[ic_cdk_macros::update]
async fn get_erc20_redeem_signature(
    token_address: String,
    amount: Nat,
    receiver: String,
    hash: String,
    nonce: Nat,
    chain_id: Nat,
    is_wrapped: bool,
    network: String
) -> Vec<u8> {
    let decode_hash = hex::decode(hash)
        .expect("failed to decode hash");

    let node_url = format!(
        "https://{}.infura.io/v3/{}",
        Network::from(&network).as_str(),
        INPURA_API_KEY
    );

    let w3 = Web3::new(
        ICHttp::new(&node_url, None, None).unwrap()
    );

    let tx_receipt = w3.eth()
        .transaction_receipt(H256::from_slice(&decode_hash))
        .await
        .expect("failed to get a tx receipt")
        .ok_or_else(|| panic!("tx doesn't exist or wasn't indexed yet"))
        .expect("something mysterious has happened");

    if tx_receipt.status.unwrap_or_default().is_zero() {
        panic!("tx has failed");
    }

    let token_address = Address::from_slice(&hex::decode(&token_address)
        .expect("failed to decode token address"));
    let amount = Uint::from_dec_str(&nat_to_normal_str(&amount))
        .expect("failed to parse amount");
    let receiver = Address::from_slice(&hex::decode(&receiver)
        .expect("failed to decode receiver"));
    let nonce = Uint::from_dec_str(&nat_to_normal_str(&nonce))
        .expect("failed to parse nonce");
    let chain_id = Uint::from_dec_str(&nat_to_normal_str(&chain_id))
        .expect("failed to parse chain_id");

    let data = Token::Tuple(vec![
        Token::Address(token_address),
        Token::Uint(amount),
        Token::Address(receiver),
        Token::FixedBytes(decode_hash.clone()),
        Token::Uint(nonce),
        Token::Uint(chain_id),
        Token::Bool(is_wrapped)
    ]);
    
    let encoded_data = ethabi::encode(&[data]);

    let hashed_data = keccak256(&encoded_data);

    let message_hash = hash_message(&hashed_data).as_bytes().to_vec();

    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];

    let call_args = SignWithEcdsaArgument {
        message_hash: message_hash.clone(),
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: KEY_NAME.to_string(),
        }
    };
    
    let signature = match sign_with_ecdsa(call_args).await {
        Ok((response,)) => response.signature,
        Err((rejection_code, msg)) => {
            panic!("failed to sign a hash. Rejection code: {:?}, msg: {:?}", rejection_code, msg);
        }
    };

    // let k256_signature = Signature::from_bytes(GenericArray::from_slice(&signature))
    //     .expect("failed to convert a byte array to a k256 signature");

    ic_cdk::println!("Signature: {}", hex::encode(&signature));

    let eth_addr = eth_address().await;

    ic_cdk::println!("Eth addr: {}", eth_addr);

    // let secp = Secp256k1::verification_only();

    ic_cdk::println!("msg: {}", hex::encode(&message_hash));

    // let msg = Message::from_slice(&message_hash).unwrap();

    // let sig = ecdsa::Signature::from_compact(&signature).unwrap();

    // let pk = PublicKey::from_slice(eth_addr.as_bytes()).unwrap();

    // match secp.verify_ecdsa(&msg, &sig, &pk) {
    //     Ok(_) => ic_cdk::println!("Signature verified"),
    //     Err(err) => ic_cdk::println!("Signature unverified, err: {:?}", err)
    // };

    // let v: u8 = if bool::from(k256_signature.s().is_high()) { 28 } else { 27 };

    // signature.push(v);

    signature
}

fn nat_to_normal_str(nat: &Nat) -> String {
    nat.to_string().chars().filter(|&c| c != '_').collect()
}

// #[cfg(test)]
// mod tests {
//     use crate::get_erc20_redeem_signature;
//     use candid::Nat;


//     #[tokio::test]
//     async fn it_works() {
//         let result = get_erc20_redeem_signature(
//             String::from("ac74c64A7cFdBb33c33D2827569FE6EaF9a677dB"),
//             Nat::from(100000),
//             String::from("E86C4A45C1Da21f8838a1ea26Fc852BD66489ce9"),
//             String::from("5edcd76efb884194fc1f7d348ffc4ef93c611e3ffa89aca3a2dcf0131e2844df"),
//             Nat::from(0),
//             Nat::from(11155111),
//             true,
//             String::from("goerli"),
//         ).await;

//         println!("Output Signature: {:?}", hex::encode(&result));
//     }
// }
