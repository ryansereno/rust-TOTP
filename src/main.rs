use hmacsha1::hmac_sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use std::io;

const TOTP_VALIDITY_DURATION: u128 = 30000; // 30 seconds
const TOTP_LENGTH: u32 = 6;

fn main() ->io::Result<()> {
    let mut key = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut key)?;

    //let key = String::from("LbfGTsah9e2cpKWgCMvDUkvdz2Fx2p");

    loop {
        let totp = generate_htop(key.clone(), get_counter());
        println!("Your passcode: {:06}", totp);
        thread::sleep(time::Duration::from_millis(TOTP_VALIDITY_DURATION as u64));
    }

}

fn create_message_from_counter(mut counter: u128) -> [u8; 8] {
    let mut buff = [0; 8];
    for i in 0..8 {
        buff[7 - i] = (counter & 0xff) as u8;
        counter = counter >> 8;
    }
    buff
}

fn compute_dynamic_truncation(bytes: &[u8]) -> u32 {
    let bytes = bytes.to_vec();
    let offset = (bytes[bytes.len() - 1] & 0xf) as usize;
    (((bytes[offset] & 0x7f) as u32) << 24)
        | (((bytes[offset + 1] & 0xff) as u32) << 16)
        | (((bytes[offset + 2] & 0xff) as u32) << 8)
        | (bytes[offset + 3] & 0xff) as u32
}

fn generate_htop(key: String, counter: u128) -> u32 {
    let message = create_message_from_counter(counter);
    let hmac_value = hmac_sha1(key.as_bytes(), &message);
    let dynamic_truncation = compute_dynamic_truncation(&hmac_value);

    dynamic_truncation % 10u32.pow(TOTP_LENGTH)
}

fn current_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Could not get the current timestamp")
        .as_millis()
}

fn get_counter() -> u128 {
    current_timestamp() / TOTP_VALIDITY_DURATION
}

