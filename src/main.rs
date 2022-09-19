use hmacsha1::hmac_sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{thread, time};
use std::io;
use base32::{encode, decode};

const TOTP_DURATION: u128 = 30000; 
const TOTP_LENGTH: u32 = 6;

fn main() ->io::Result<()> {
    let mut key = String::new();
    println!("Enter secret key: ");
    let stdin = io::stdin();

    stdin.read_line(&mut key)?;

    // TOTP private keys are usually shared in the Base32 encoded form. This is to prevent human
    // error when reading and inputing. Base32 is alphanumeric ONLY and is in all caps.
    // This base32 string needs to be decoded prior to passing into the HMAC algorithm

    loop {
        let totp = generate_htop(key.clone(), get_count());
        println!("Your passcode: {:06}", totp);
        thread::sleep(time::Duration::from_millis(TOTP_DURATION as u64));
    }
}

fn current_unix_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Current time not available")
        .as_millis()
}

fn get_count() -> u128 {
    current_unix_time() / TOTP_DURATION
}

fn counter_to_bits(mut counter: u128) -> [u8; 8] {
    let mut buff = [0; 8];
    for i in 0..8 {
        buff[7 - i] = (counter & 0xff) as u8;
        counter = counter >> 8;
    }
    buff
}

fn dynamic_truncation(bytes: &[u8]) -> u32 {
    let bytes = bytes.to_vec();
    let offset = (bytes[bytes.len() - 1] & 0xf) as usize;
    (((bytes[offset] & 0x7f) as u32) << 24)
        | (((bytes[offset + 1] & 0xff) as u32) << 16)
        | (((bytes[offset + 2] & 0xff) as u32) << 8)
        | (bytes[offset + 3] & 0xff) as u32
}

fn generate_htop(key: String, counter: u128) -> u32 {
    let message = counter_to_bits(counter);
    let hmac_value = hmac_sha1(key.as_bytes(), &message);
    let dynamic_truncation = dynamic_truncation(&hmac_value);

    dynamic_truncation % 10u32.pow(TOTP_LENGTH)
}



