use hex;
use simple_asn1::{from_der, oid, ASN1Block, ASN1Class, BigUint};

pub fn parse_signed_data(der_bytes: &[u8]) -> Result<(String, String, String), String> {
    let asn1_blocks = from_der(der_bytes).expect("Failed to parse DER");

    // The SignedData should be the first (and only) top-level element
    let content_info = match asn1_blocks.get(0) {
        Some(ASN1Block::Sequence(_, children)) => children,
        _ => panic!("DER is not a valid ASN.1 sequence"),
    };

    // Step 1: Content Type
    let content_type_oid = match content_info.get(0) {
        Some(ASN1Block::ObjectIdentifier(_, oid)) => oid,
        _ => panic!("ContentInfo missing contentType OID"),
    };

    assert_eq!(
        *content_type_oid,
        oid!(1, 2, 840, 113549, 1, 7, 2),
        "Not a PKCS#7 signedData"
    );

    // OID 1.2.840.113549.1.7.2 = signedData content type&#8203;:contentReference[oaicite:6]{index=6}
    // / Step 2: SignedData content
    let signed_data_block = content_info.get(1).expect("Missing SignedData content");

    // 2) Peel off the outer tag if needed
    let signed_children = match signed_data_block {
        // explicit [15] check for digital locker might need to change this logic
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => match &**inner {
            ASN1Block::Sequence(_, children) => children.clone(),
            _ => panic!("Explicit SignedData is not a SEQUENCE"),
        },

        // implicit/unknown context-specific → re-parse
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _constructed, 0, _len, data) => {
            let parsed =
                from_der(data).map_err(|e| format!("Failed to parse inner SignedData: {}", e));

            let parsed = parsed.expect("Failed to parse inner SignedData");
            match parsed.into_iter().next() {
                Some(ASN1Block::Sequence(_, children)) => children,
                _ => panic!("Inner SignedData is not a SEQUENCE"),
            }
        }

        // maybe we got the SEQUENCE directly
        ASN1Block::Sequence(_, children) => children.clone(),
        other => panic!("Unexpected ContentInfo content format: {:?}", other),
    };

    // 3) Version (INTEGER) at idx 0
    let version = match signed_children.get(0) {
        Some(ASN1Block::Integer(_, v)) => v.clone(),
        _ => panic!("SignedData version not found"),
    };

    // 4) DigestAlgorithms (SET) at idx 1
    let digest_algos = match signed_children.get(1) {
        Some(ASN1Block::Set(_, algos)) => algos.clone(),
        _ => panic!("SignedData digestAlgorithms set not found"),
    };
    let digest_algo = digest_algos.get(0).expect("No digest algorithm found");

    let cert_block = signed_children
        .get(signed_children.len() - 2)
        .expect("No certificate block found");

    let certs: Vec<ASN1Block> = match cert_block {
        // any [n] wrapper
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
            let parsed = from_der(data).expect("Failed to parse certificate wrapper");
            match &parsed[0] {
                ASN1Block::Set(_, certs) => certs.clone(),
                ASN1Block::Sequence(_, single) => {
                    // single‑cert case
                    vec![ASN1Block::Sequence(0, single.clone())]
                }
                other => panic!("Unexpected inside certificate wrapper: {:?}", other),
            }
        }
        ASN1Block::Set(_, certs) => certs.clone(),

        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner_block) => {
            match &**inner_block {
                ASN1Block::Sequence(_, certs) => certs.clone(),
                _ => panic!("Unexpected content inside Explicit block"),
            }
        }
        other => panic!("Unexpected certificates block: {:?}", other),
    };

    // 6) Take the first certificate (assume signer’s)
    let signer_cert = match &certs[0] {
        ASN1Block::Sequence(_, cert_fields) => cert_fields,
        other => panic!("Expected cert as SEQUENCE, got {:?}", other),
    };

    // 7) Drill into tbsCertificate (child[0] of Certificate SEQUENCE)
    let tbs = match &signer_cert[0] {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, _) => &signer_cert,

        ASN1Block::Sequence(_, tbs_fields) => tbs_fields,
        _ => panic!("tbsCertificate not found"),
    };

    let spki = tbs
        .iter()
        .find_map(|block| {
            if let ASN1Block::Sequence(_, spki_fields) = block {
                // check for rsaEncryption OID in spki_fields[0]
                if let ASN1Block::Sequence(_, alg) = &spki_fields[0] {
                    if let Some(ASN1Block::ObjectIdentifier(_, o)) = alg.get(0) {
                        if *o == oid!(1, 2, 840, 113549, 1, 1, 1) {
                            return Some(spki_fields);
                        }
                    }
                }
            }
            None
        })
        .expect("subjectPublicKeyInfo not found");

    // 9) Extract BIT STRING (DER of RSAPublicKey)
    let pubkey_der = match &spki[1] {
        ASN1Block::BitString(_, _unused, data) => data,
        other => panic!("Expected BIT STRING for public key, got {:?}", other),
    };

    // 10) Parse RSAPublicKey (SEQUENCE of two INTEGERs)
    let rsa_blocks = from_der(pubkey_der).expect("Failed to parse RSAPublicKey DER");
    let rsa_seq = match &rsa_blocks[0] {
        ASN1Block::Sequence(_, items) => items,
        _ => panic!("RSAPublicKey not a SEQUENCE"),
    };

    // 11) Print modulus and exponent
    if let ASN1Block::Integer(_, modulus) = &rsa_seq[0] {
        println!(
            "Modulus (hex): {}",
            hex::encode(modulus.to_signed_bytes_be())
        );
    } else {
        panic!("Modulus not found");
    }

    if let ASN1Block::Integer(_, exponent) = &rsa_seq[1] {
        println!("Exponent (decimal): {}", exponent);
    } else {
        panic!("Exponent not found");
    }
    // 5) SignerInfos is the *last* element, must be a SET
    let signer_infos = match signed_children.last() {
        Some(ASN1Block::Set(_, items)) => items.clone(),
        _ => panic!("signerInfos set not found"),
    };

    // 6) Take the first SignerInfo (assume exactly one)
    // single singer info for now
    // fields layout: [version, issuer_and_serial, digest_algo, signed_attrs, signature_algo, signature]
    let signer_fields = match signer_infos.get(0) {
        Some(ASN1Block::Sequence(_, fields)) => fields.clone(),
        _ => panic!("SignerInfo is not a SEQUENCE"),
    };

    let signature_algo = match signer_fields.get(4) {
        Some(ASN1Block::Sequence(_, fields)) => fields.clone(),
        _ => panic!("SignatureAlgorithm is not a SEQUENCE"),
    };
    let sig_alg_oid = match signature_algo.get(0) {
        Some(ASN1Block::ObjectIdentifier(_o, oid)) => oid,
        _ => panic!("Signature algorithm OID not found"),
    };

    let rsa_encryption_oid = oid!(1, 2, 840, 113549, 1, 1, 1); // rsaEncryption OID
                                                               // OIDs for combined hash RSA signatures:
    let oid_sha1_rsa = oid!(1, 2, 840, 113549, 1, 1, 5);
    let oid_sha256_rsa = oid!(1, 2, 840, 113549, 1, 1, 11);
    let oid_sha384_rsa = oid!(1, 2, 840, 113549, 1, 1, 12);
    let oid_sha512_rsa = oid!(1, 2, 840, 113549, 1, 1, 13);
    let oid_sha224_rsa = oid!(1, 2, 840, 113549, 1, 1, 14);
    // OIDs for standalone digest algorithms (for reference)
    let oid_sha1 = oid!(1, 3, 14, 3, 2, 26);
    let oid_sha256 = oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
    let oid_sha384 = oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);
    let oid_sha512 = oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);
    let oid_sha224 = oid!(2, 16, 840, 1, 101, 3, 4, 2, 4);
    let alg_name = if *sig_alg_oid == oid_sha256_rsa {
        "sha256WithRSAEncryption"
    } else if *sig_alg_oid == oid_sha384_rsa {
        "sha384WithRSAEncryption"
    } else if *sig_alg_oid == oid_sha512_rsa {
        "sha512WithRSAEncryption"
    } else if *sig_alg_oid == oid_sha1_rsa {
        "sha1WithRSAEncryption"
    } else if *sig_alg_oid == oid_sha224_rsa {
        "sha224WithRSAEncryption"
    } else if *sig_alg_oid == rsa_encryption_oid {
        // If just rsaEncryption, infer from digestAlgorithm (for example, SHA-256)
        if let ASN1Block::Sequence(_o, digest_seq) = digest_algo {
            if let Some(ASN1Block::ObjectIdentifier(_o, digest_oid)) = digest_seq.get(0) {
                if *digest_oid == oid_sha256 {
                    "sha256WithRSAEncryption"
                } else if *digest_oid == oid_sha384 {
                    "sha384WithRSAEncryption"
                } else if *digest_oid == oid_sha512 {
                    "sha512WithRSAEncryption"
                } else if *digest_oid == oid_sha1 {
                    "sha1WithRSAEncryption"
                } else if *digest_oid == oid_sha224 {
                    "sha224WithRSAEncryption"
                } else {
                    "rsaEncryption (unknown hash)"
                }
            } else {
                "rsaEncryption (unknown hash)"
            }
        } else {
            "rsaEncryption"
        }
    } else {
        "UnknownSignatureAlgorithm"
    };
    println!("Signature Algorithm: {}", alg_name);

    let signature_block = signer_fields.get(5).expect("Signature block not found");
    let sig_bytes = match signature_block {
        ASN1Block::OctetString(_, bs) => bs.clone(),
        ASN1Block::BitString(_, _, bs) => bs.clone(),
        other => panic!("{}", format!("Unexpected signature block: {:?}", other)),
    };

    let signature_hex = hex::encode(&sig_bytes);
    let public_key = hex::encode(&pubkey_der);
    let signature_algorithm = alg_name.to_string();

    Ok((public_key, signature_hex, signature_algorithm))
}
#[cfg(test)]
mod tests {

    use super::*;
    use crate::get_signature_der;
    use sha1::{Digest, Sha1};
    use std::fs;

    #[test]
    fn one() {
        let pdf_bytes = fs::read("../sample-pdfs/digitally_signed.pdf")
            .expect("Failed to read digitally_signed.pdf");

        let (der, signed_data) = get_signature_der(&pdf_bytes).expect("Failed to get signed data");

        let (modulus_hex, signature_hex, signature_algorithm) =
            parse_signed_data(&der).expect("Failed to parse signed data");

        let modulus = BigUint::from_bytes_be(&hex::decode(modulus_hex).unwrap());
        let signature = hex::decode(signature_hex).unwrap();
        let signed_data_hex = hex::encode(&signed_data);

        // fs::write("../sample-pdfs/signed_data_hex.txt", &signed_data_hex)
        //     .expect("Failed to write signed_data_hex.txt");

        // 2) Decode to raw bytes
        // let der_bytes = hex::decode(&hex_der).expect("Failed to hex-decode your DER file contents");

        // let modulus = BigUint::from_bytes_be(&hex::decode(modulus_hex).unwrap());
        // let signature = hex::decode(signature_hex).unwrap();

        // let public_key = RsaPublicKey::new(
        //     rsa::BigUint::from_bytes_be(&modulus.to_bytes_be()),
        //     rsa::BigUint::from_bytes_be(&exponent.to_bytes_be()),
        // )
        // .unwrap();
    }

    #[test]
    fn two() {
        let pdf_bytes = fs::read("../samples-private/bank-cert.pdf")
            .expect("Failed to read digitally_signed.pdf");

        let (der, signed_data) = get_signature_der(&pdf_bytes).expect("Failed to get signed data");

        let (modulus_hex, signature_hex, signature_algorithm) =
            parse_signed_data(&der).expect("Failed to parse signed data");

        let modulus = BigUint::from_bytes_be(&hex::decode(modulus_hex).unwrap());
        let signature = hex::decode(signature_hex).unwrap();
        let signed_data_hex = hex::encode(&signed_data);

        // fs::write("../sample-pdfs/signed_data_hex.txt", &signed_data_hex)
        //     .expect("Failed to write signed_data_hex.txt");

        // 2) Decode to raw bytes
        // let der_bytes = hex::decode(&hex_der).expect("Failed to hex-decode your DER file contents");

        // let modulus = BigUint::from_bytes_be(&hex::decode(modulus_hex).unwrap());
        // let signature = hex::decode(signature_hex).unwrap();

        // let public_key = RsaPublicKey::new(
        //     rsa::BigUint::from_bytes_be(&modulus.to_bytes_be()),
        //     rsa::BigUint::from_bytes_be(&exponent.to_bytes_be()),
        // )
        // .unwrap();
    }
}
