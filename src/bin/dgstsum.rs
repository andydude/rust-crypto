extern crate crypto;
use std::io::Reader;
use crypto::digest::Digest;

pub fn hash_algorithm_from_lower(name: &str) -> Option<Box<Digest+'static>> {
    match name {
        "-md5" => Some(Box::new(crypto::md5::Md5::new())),
        "-sha1" => Some(Box::new(crypto::sha1::Sha1::new())),
        "-sha224" => Some(Box::new(crypto::sha2::Sha224::new())),
        "-sha256" => Some(Box::new(crypto::sha2::Sha256::new())),
        "-sha384" => Some(Box::new(crypto::sha2::Sha384::new())),
        "-sha512" => Some(Box::new(crypto::sha2::Sha512::new())),
        "-sha512224" => Some(Box::new(crypto::sha2::Sha512Trunc224::new())),
        "-sha512256" => Some(Box::new(crypto::sha2::Sha512Trunc256::new())),
        "-ripemd160" => Some(Box::new(crypto::ripemd160::Ripemd160::new())),
        "-blake2b" => Some(Box::new(crypto::blake2b::Blake2b::new(64))),
        _ => None
    }
}

fn main() {
    // get message
    let mut reader = std::io::stdin();
    let message: Vec<u8> = reader.read_to_end().unwrap();

    // get hash algorithm
    let args = std::os::args();
    let command: &str = args[1].as_slice();
    let mut hasher = hash_algorithm_from_lower(command).unwrap();

    // compute hash
    hasher.input(message.as_slice());
    println!("{}", hasher.result_str());
}
