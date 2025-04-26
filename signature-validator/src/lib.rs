pub mod pkcs7_signature;
pub mod signed_bytes_extractor;
use pkcs7_signature::{parse_signed_data, VerifierParams};
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signed_bytes_extractor::get_signature_der;
use simple_asn1::OID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Sha1WithRsaEncryption,
    Sha256WithRsaEncryption,
    Sha384WithRsaEncryption,
    Sha512WithRsaEncryption,
    RsaEncryption,
    RsaEncryptionWithUnknownHash(OID),
    Unknown(OID),
}
pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> Result<bool, String> {
    let (signature_der, signed_data) =
        get_signature_der(pdf_bytes).expect("failed to extract signed data");

    let verifier_params: VerifierParams =
        parse_signed_data(&signature_der).expect("failed to parse signed data");

    // CHECK 1
    // Extracted messageDigest == HASH(signed_data)

    let calculated_signed_data_hash: Vec<u8> = match verifier_params.algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => {
            let mut hasher = Sha1::new();
            hasher.update(&signed_data);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha256WithRsaEncryption => {
            let mut hasher = Sha256::new();
            hasher.update(&signed_data);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha384WithRsaEncryption => {
            let mut hasher = Sha384::new();
            hasher.update(&signed_data);
            hasher.finalize().to_vec()
        }
        SignatureAlgorithm::Sha512WithRsaEncryption => {
            let mut hasher = Sha512::new();
            hasher.update(&signed_data);
            hasher.finalize().to_vec()
        }
        _ => return Err("Unsupported signature algorithm".to_string()),
    };

    assert_eq!(
        hex::encode(verifier_params.signed_data_message_digest),
        hex::encode(calculated_signed_data_hash)
    );

    // CHECK 2
    let pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&verifier_params.modulus),
        rsa::BigUint::from_bytes_be(&verifier_params.exponent.to_bytes_be()),
    )
    .map_err(|e| e.to_string())?;

    let padding: Pkcs1v15Sign;

    match verifier_params.algorithm {
        SignatureAlgorithm::Sha1WithRsaEncryption => {
            padding = Pkcs1v15Sign::new::<Sha1>();
        }

        SignatureAlgorithm::Sha256WithRsaEncryption => {
            padding = Pkcs1v15Sign::new::<Sha256>();
        }
        SignatureAlgorithm::Sha384WithRsaEncryption => {
            padding = Pkcs1v15Sign::new::<Sha384>();
        }
        SignatureAlgorithm::Sha512WithRsaEncryption => {
            padding = Pkcs1v15Sign::new::<Sha512>();
        }
        SignatureAlgorithm::RsaEncryption => {
            todo!()
        }
        SignatureAlgorithm::RsaEncryptionWithUnknownHash(_) => todo!(),
        SignatureAlgorithm::Unknown(_) => todo!(),
    }

    let is_verified = pub_key
        .verify(
            padding,
            &verifier_params.signed_attr_digest,
            &verifier_params.signature,
        )
        .is_ok();

    Ok(is_verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    // PUBLIC PDF
    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");

    // PRIVATE PDF
    static BANK_PDF_BYTES: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");
    static PAN_PDF_BYTES: &[u8] = include_bytes!("../../samples-private/pan-cert.pdf");

    #[test]
    fn test_sha1_pdf() {
        let res = verify_pdf_signature(SAMPLE_PDF_BYTES);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sha256_pdf() {
        let res = verify_pdf_signature(BANK_PDF_BYTES);
        assert!(res.is_ok());
    }

    #[test]
    fn test_sha1_with_rsa_encryption() {
        let res = verify_pdf_signature(PAN_PDF_BYTES);
        assert!(res.is_ok());
    }
}
