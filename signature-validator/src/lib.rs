pub mod pkcs7_signature;
pub mod signed_bytes_extractor;
use hex::decode;
use pkcs7_signature::{parse_signed_data, SignedDataInfo};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use signed_bytes_extractor::get_signature_der;

pub fn validate(pdf_bytes: &[u8]) -> bool {
    let (signature_der, signed_data) =
        get_signature_der(pdf_bytes).expect("failed to extract signed data");

    let SignedDataInfo {
        signature: signature_hex,
        algorithm: signature_algorithm,
        modulus: modulus_hex,
        exponent,
    } = parse_signed_data(&signature_der).expect("Failed to parse signed data");

    let signature_bytes = decode(&signature_hex).expect("Failed to decode signature hex");
    let modulus_bytes = decode(&modulus_hex).expect("Failed to decode modulus hex");

    let n = rsa::BigUint::from_bytes_be(&modulus_bytes);
    let e = exponent;

    let public_key = RsaPublicKey::new(n, e).expect("Failed to create public key");

    let mut hasher = Sha256::new();
    hasher.update(signed_data);
    let hashed_msg = hasher.finalize();

    let verification = public_key.verify(
        Pkcs1v15Sign::new_unprefixed(),
        &hashed_msg,
        &signature_bytes,
    );

    let verified = match verification {
        Ok(_) => {
            println!("Signature verified successfully.");
            true
        }
        Err(e) => {
            println!("Failed to verify signature: {:?}", e);
            false
        }
    };

    verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Digest;
    use std::fs;

    #[test]

    fn validator() {
        let pdf_bytes =
            fs::read("../samples-private/pan-cert.pdf").expect("Failed to read PDF file");

        let is_valid = validate(&pdf_bytes);
        assert!(is_valid)
    }
}
