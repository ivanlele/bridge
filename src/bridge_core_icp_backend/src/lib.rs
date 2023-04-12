use candid::Nat;
use ic_cdk::api::management_canister::ecdsa::{
    sign_with_ecdsa, SignWithEcdsaArgument, EcdsaKeyId, EcdsaCurve
};
use ic_web3::types::H256;
use ic_cdk::api::management_canister::http_request::{
    HttpResponse, TransformArgs,
};
use ethabi::{Token, Address, Uint};
use ic_web3::transports::ICHttp;
use ic_web3::Web3;
use ic_web3::ic::get_eth_addr;
use ic_web3::types::H160;
use ic_web3::signing::{hash_message, keccak256};
use thiserror::Error;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use secp256k1::{PublicKey, Secp256k1};

const KEY_NAME: &str = "dfx_test_key";
const INPURA_API_KEY: &str = "d009354476b140008dd04c741c00341b";

type Result<T, E> = std::result::Result<T, E>;

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

#[derive(Debug, Error)]
pub enum EncodePackedError {
    #[error("This token cannot be encoded in packed mode: {0:?}")]
    InvalidToken(Token),

    #[error("FixedBytes token length > 32")]
    InvalidBytesLength,
}

#[ic_cdk_macros::query]
fn transform(response: TransformArgs) -> HttpResponse {
    response.response
}

#[ic_cdk_macros::update]
async fn eth_address() -> Result<String, String> {
    match get_eth_addr(None, None, KEY_NAME.to_string()).await {
        Ok(eth_addr) => Ok(hex::encode(eth_addr)),
        Err(err) => Err(err)
    }
}

#[ic_cdk_macros::update]
async fn get_erc20_redeem_signature(
    token_address: String,
    amount: Nat,
    receiver: String,
    tx_hash: String,
    nonce: Nat,
    chain_id: Nat,
    is_wrapped: bool,
    network: String
) -> Result<String, String> {
    let node_url = format!(
        "https://{}.infura.io/v3/{}",
        Network::from(&network).as_str(),
        INPURA_API_KEY
    );

    let w3 = Web3::new(
        ICHttp::new(&node_url, None, None).unwrap()
    );

    let decoded_hash = hex::decode(tx_hash)
        .map_err(|err| format!("failed to decode the tx hash: {}", err))?;

    let tx_receipt = w3.eth()
        .transaction_receipt(H256::from_slice(&decoded_hash))
        .await
        .map_err(|err| format!("failed to get a tx receipt: {}", err))?
        .ok_or_else(|| return "the tx doesn't exist or wasn't indexed yet".to_string())?;

    if tx_receipt.status.unwrap_or_default().is_zero() {
        return Err("The tx has failed".to_string());
    }

    let token_address = Address::from_slice(&hex::decode(&token_address)
        .map_err(|err| format!("failed to decode the token address: {}", err))?);
    let amount = Uint::from_dec_str(&nat_to_normal_str(&amount))
        .map_err(|err| format!("failed to decode the amount: {}", err))?;
    let receiver = Address::from_slice(&hex::decode(&receiver)
        .map_err(|err| format!("failed to decode the receiver: {}", err))?);
    let nonce = Uint::from_dec_str(&nat_to_normal_str(&nonce))
        .map_err(|err| format!("failed to decode the nonce: {}", err))?;
    let chain_id = Uint::from_dec_str(&nat_to_normal_str(&chain_id))
        .map_err(|err| format!("failed to decode the chain id: {}", err))?;

    let data = vec![
        Token::Address(token_address),
        Token::Uint(amount),
        Token::Address(receiver),
        Token::FixedBytes(decoded_hash.clone()),
        Token::Uint(nonce),
        Token::Uint(chain_id),
        Token::Bool(is_wrapped)
    ];
    
    let encoded_data = encode_packed(&data)
        .map_err(|err| format!("failed to perform a packing encoding: {}", err))?;

    let hashed_data = keccak256(&encoded_data);

    let msg_hash = hash_message(&hashed_data).as_bytes().to_vec();

    let derivation_path = vec![ic_cdk::id().as_slice().to_vec()];

    let call_args = SignWithEcdsaArgument {
        message_hash: msg_hash.clone(),
        derivation_path,
        key_id: EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: KEY_NAME.to_string(),
        }
    };
    
    let mut signature = match sign_with_ecdsa(call_args).await {
        Ok((response,)) => response.signature,
        Err((rejection_code, msg)) => {
            return Err(format!("failed to sign a hash. Rejection code: {:?}, msg: {:?}", rejection_code, msg));
        }
    };

    let public_key = get_eth_addr(None, None, KEY_NAME.to_string())
        .await
        .map_err(|err| format!("failed to get an eth address: {}", err))?;

    let v: u8 = get_eth_v(&signature, &msg_hash, &public_key)
        .map_err(|err| format!("failed to get a v: {}", err))?;

    signature.push(v);

    Ok(format!("0x{}", hex::encode(signature)))
}

fn get_eth_v(signature: &[u8], msg: &[u8], public_key: &H160) -> Result<u8, String> {
    let sig = Signature::from_slice(&signature)
        .map_err(|err| format!("failed to decode a signature: {}", err))?;

    let recovery_id = RecoveryId::from_byte(0).unwrap();

    let recovered_key = VerifyingKey::recover_from_msg(msg, &sig, recovery_id)
        .map_err(|err| format!("failed to recover a key: {}", err))?;

    ic_cdk::println!("First pk {}", hex::encode(keccak256(&recovered_key.to_sec1_bytes())));

    if keccak256(&recovered_key.to_sec1_bytes()) == public_key.as_bytes() {
        return Ok(27);
    }

    let recovery_id = RecoveryId::from_byte(1).unwrap();

    let recovered_key = VerifyingKey::recover_from_msg(msg, &sig, recovery_id)
        .map_err(|err| format!("failed to recover a key: {}", err))?;

        ic_cdk::println!("Second pk {}", hex::encode(keccak256(&recovered_key.to_sec1_bytes())));

    if keccak256(&recovered_key.to_sec1_bytes()) == public_key.as_bytes() {
        return Ok(28);
    }

    Err("failed to get a v".to_string())
}

fn nat_to_normal_str(nat: &Nat) -> String {
    nat.to_string().chars().filter(|&c| c != '_').collect()
}

fn encode_packed(tokens: &[Token]) -> Result<Vec<u8>, EncodePackedError> {
    let mut max = 0;
    for token in tokens {
        check(token)?;
        max += max_encoded_length(token);
    }

    let mut bytes = Vec::with_capacity(max);
    for token in tokens {
        encode_token(token, &mut bytes, false);
    }
    Ok(bytes)
}

fn max_encoded_length(token: &Token) -> usize {
    match token {
        Token::Int(_) | Token::Uint(_) | Token::FixedBytes(_) => 32,
        Token::Address(_) => 20,
        Token::Bool(_) => 1,
        Token::Array(vec) | Token::FixedArray(vec) | Token::Tuple(vec) => {
            vec.iter().map(|token| max_encoded_length(token).max(32)).sum()
        }
        Token::Bytes(b) => b.len(),
        Token::String(s) => s.len(),
    }
}

fn check(token: &Token) -> Result<(), EncodePackedError> {
    match token {
        Token::FixedBytes(vec) if vec.len() > 32 => Err(EncodePackedError::InvalidBytesLength),

        Token::Tuple(_) => Err(EncodePackedError::InvalidToken(token.clone())),
        Token::Array(vec) | Token::FixedArray(vec) => {
            for t in vec.iter() {
                if t.is_dynamic() || matches!(t, Token::Array(_)) {
                    return Err(EncodePackedError::InvalidToken(token.clone()))
                }
                check(t)?;
            }
            Ok(())
        }

        _ => Ok(()),
    }
}

fn encode_token(token: &Token, out: &mut Vec<u8>, in_array: bool) {
    match token {
        Token::Address(addr) => {
            if in_array {
                out.extend_from_slice(&[0; 12]);
            }
            out.extend_from_slice(&addr.0)
        }
        Token::Int(n) | Token::Uint(n) => {
            let mut buf = [0; 32];
            n.to_big_endian(&mut buf);
            out.extend_from_slice(&buf);
        }
        Token::Bool(b) => {
            if in_array {
                out.extend_from_slice(&[0; 31]);
            }
            out.push((*b) as u8);
        }
        Token::FixedBytes(bytes) => {
            out.extend_from_slice(bytes);
            if in_array {
                let mut remaining = vec![0; 32 - bytes.len()];
                out.append(&mut remaining);
            }
        }

        Token::Bytes(bytes) => out.extend_from_slice(bytes),
        Token::String(s) => out.extend_from_slice(s.as_bytes()),
        Token::Array(vec) | Token::FixedArray(vec) => {
            for token in vec {
                encode_token(token, out, true);
            }
        }

        token => unreachable!("Uncaught invalid token: {token:?}"),
    }
}
#[cfg(test)]
mod tests {
    use ethabi::{Token, Address, Uint};
    use ic_web3::signing::{keccak256, hash_message};
    use secp256k1::{Secp256k1, Message, SecretKey, PublicKey};

    use crate::encode_packed;

    const ECDSA_HEX_PRIVATE_KEY: &[u8] = "63dd6406ece1e459644301db883394a238ba4f1a2ff54249da7551f20bc2f8a9".as_bytes();

    lazy_static::lazy_static! {
        static ref TOKEN_ADDRESS: Address = Address::from_slice(&hex::decode("ac74c64A7cFdBb33c33D2827569FE6EaF9a677dB").unwrap());
        static ref AMOUNT: Uint = Uint::from(100000);
        static ref RECEIVER: Address = Address::from_slice(&hex::decode("E86C4A45C1Da21f8838a1ea26Fc852BD66489ce9").unwrap());
        static ref NONCE: Uint = Uint::from(0);
        static ref CHAID_ID: Uint = Uint::from(11155111);
        static ref TX_HASH: Vec<u8> = hex::decode("5edcd76efb884194fc1f7d348ffc4ef93c611e3ffa89aca3a2dcf0131e2844df").unwrap();
    }

    #[test]
    fn hash() {
        let data = Token::Tuple(vec![
            Token::Address(*TOKEN_ADDRESS),
            Token::Uint(*AMOUNT),
            Token::Address(*RECEIVER),
            Token::FixedBytes((*TX_HASH.clone()).to_vec()),
            Token::Uint(*NONCE),
            Token::Uint(*CHAID_ID),
            Token::Bool(true)
        ]);
        
        let encoded_data = ethabi::encode(&[data]);
        println!("Encoded data: {}", hex::encode(&encoded_data));
        
        let hashed_data = keccak256(&encoded_data);
        println!("Hashed data: {}", hex::encode(&hashed_data));
    }

    #[test]
    fn sign() {
        let data = vec![
            Token::Address(*TOKEN_ADDRESS),
            Token::Uint(*AMOUNT),
            Token::Address(*RECEIVER),
            Token::FixedBytes((*TX_HASH.clone()).to_vec()),
            Token::Uint(*NONCE),
            Token::Uint(*CHAID_ID),
            Token::Bool(true)
        ];
        
        let encoded_data = encode_packed(&data).unwrap();

        println!("Encoded data: {}", hex::encode(&encoded_data));

        let hashed_data = keccak256(&encoded_data);

        println!("Hashed data: {}", hex::encode(&hashed_data));

        let secret_key = SecretKey::from_slice(&hex::decode(ECDSA_HEX_PRIVATE_KEY).unwrap()).unwrap();

        let secp = Secp256k1::new();
        
        let hashed_data = hash_message(&hashed_data);
        let eth_data = hashed_data.as_bytes();

        let msg = Message::from_slice(eth_data)
            .expect("32 bytes");
        
        println!("Msg: {}", hex::encode(eth_data));

        let sig = secp.sign_ecdsa(&msg, &secret_key);

        let mut signature = sig.serialize_compact().to_vec();

        signature.push(28);
        
        println!("Signature: {}", hex::encode(&signature));

        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        assert!(secp.verify_ecdsa(&msg, &sig, &public_key).is_ok());
    }    
}
