use hex::encode;
use rsa::BigUint;
use simple_asn1::{from_der, oid, ASN1Block, ASN1Class, OID};

pub struct SignedDataInfo {
    pub modulus: String,
    pub exponent: BigUint,
    pub signature: String,
    pub algorithm: String,
}

pub fn parse_signed_data(der_bytes: &[u8]) -> Result<SignedDataInfo, String> {
    let blocks = from_der(der_bytes).map_err(|e| format!("DER parse error: {}", e))?;

    let content_info = extract_content_info(&blocks)?;
    let signed_children = extract_signed_children(content_info)?;

    let (modulus_bytes, exponent_big) = extract_pubkey_components(&signed_children)?;
    let signer_fields = extract_signer_fields(&signed_children)?;

    let sig_alg_oid = extract_signature_oid(&signer_fields)?;
    let alg_name = resolve_algorithm(&sig_alg_oid, &signed_children);
    let signature = extract_signature(&signer_fields)?;

    Ok(SignedDataInfo {
        modulus: encode(&modulus_bytes),
        exponent: exponent_big,
        signature,
        algorithm: alg_name.to_string(),
    })
}

fn extract_content_info(blocks: &[ASN1Block]) -> Result<&[ASN1Block], String> {
    if let Some(ASN1Block::Sequence(_, children)) = blocks.get(0) {
        // Verify contentType is signedData OID
        if let ASN1Block::ObjectIdentifier(_, oid_val) = &children[0] {
            if *oid_val != oid!(1, 2, 840, 113549, 1, 7, 2) {
                return Err("Not a SignedData contentType".into());
            }
            Ok(children)
        } else {
            Err("Missing contentType OID".into())
        }
    } else {
        Err("Top-level not a SEQUENCE".into())
    }
}

fn extract_signed_children(children: &[ASN1Block]) -> Result<Vec<ASN1Block>, String> {
    let block = children
        .get(1)
        .ok_or_else(|| "Missing SignedData content".to_string())?;

    match block {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => {
            if let ASN1Block::Sequence(_, seq_children) = &**inner {
                Ok(seq_children.clone())
            } else {
                Err("Explicit SignedData not a SEQUENCE".into())
            }
        }
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
            let parsed =
                from_der(data).map_err(|e| format!("Inner SignedData parse error: {}", e))?;
            if let ASN1Block::Sequence(_, seq_children) = &parsed[0] {
                Ok(seq_children.clone())
            } else {
                Err("Inner SignedData not a SEQUENCE".into())
            }
        }
        ASN1Block::Sequence(_, seq_children) => Ok(seq_children.clone()),
        other => Err(format!("Unexpected SignedData format: {:?}", other)),
    }
}

/// Extract both modulus and exponent from the RSA public key
fn extract_pubkey_components(children: &[ASN1Block]) -> Result<(Vec<u8>, BigUint), String> {
    // Navigate to the certificates block (usually second to last element)
    let cert_block = children
        .get(children.len().saturating_sub(2))
        .ok_or_else(|| "Certificates block not found".to_string())?;

    let certs = match cert_block {
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, _, data) => {
            let parsed = from_der(data).map_err(|e| format!("Cert wrapper parse error: {}", e))?;
            match &parsed[0] {
                ASN1Block::Set(_, items) => items.clone(),
                ASN1Block::Sequence(_, single) => vec![ASN1Block::Sequence(0, single.clone())],
                _ => return Err("Unexpected cert wrapper content".into()),
            }
        }
        ASN1Block::Set(_, items) => items.clone(),
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, inner) => {
            if let ASN1Block::Sequence(_, items) = &**inner {
                items.clone()
            } else {
                return Err("Explicit cert block not SEQUENCE".into());
            }
        }
        other => return Err(format!("Unexpected certificates block: {:?}", other)),
    };

    // Take first certificate and drill into tbsCertificate (child[0])
    let cert_fields = if let ASN1Block::Sequence(_, fields) = &certs[0] {
        fields
    } else {
        return Err("Certificate not a SEQUENCE".into());
    };

    //tbsCertificate (child[0])
    let tbs_fields = match &cert_fields[0] {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, _) => cert_fields.clone(),
        ASN1Block::Sequence(_, seq) => seq.clone(),
        _ => return Err("tbsCertificate not found".into()),
    };

    // Find subjectPublicKeyInfo within tbsCertificate
    let spki_fields = tbs_fields
        .iter()
        .find_map(|b| {
            if let ASN1Block::Sequence(_, sf) = b {
                // AlgorithmIdentifier inside sf[0]
                if let ASN1Block::Sequence(_, alg) = &sf[0] {
                    if let Some(ASN1Block::ObjectIdentifier(_, o)) = alg.get(0) {
                        if *o == oid!(1, 2, 840, 113549, 1, 1, 1) {
                            return Some(sf);
                        }
                    }
                }
            }
            None
        })
        .ok_or_else(|| "subjectPublicKeyInfo not found".to_string())?;

    let bitstring = if let ASN1Block::BitString(_, _, d) = &spki_fields[1] {
        d.clone()
    } else {
        return Err("Expected BIT STRING for public key".into());
    };

    let rsa_blocks =
        from_der(&bitstring).map_err(|e| format!("RSAPublicKey parse error: {}", e))?;
    let rsa_seq = if let ASN1Block::Sequence(_, items) = &rsa_blocks[0] {
        items
    } else {
        return Err("RSAPublicKey not a SEQUENCE".into());
    };

    let modulus = if let ASN1Block::Integer(_, m) = &rsa_seq[0] {
        m.to_signed_bytes_be()
    } else {
        return Err("Modulus not found".into());
    };

    let exponent = if let ASN1Block::Integer(_, e) = &rsa_seq[1] {
        BigUint::from_bytes_be(&e.to_signed_bytes_be())
    } else {
        return Err("Exponent not found".into());
    };

    Ok((modulus, exponent))
}
fn extract_signer_fields(children: &[ASN1Block]) -> Result<Vec<ASN1Block>, String> {
    if let Some(ASN1Block::Set(_, items)) = children.last() {
        if let ASN1Block::Sequence(_, fields) = &items[0] {
            return Ok(fields.clone());
        }
    }
    Err("SignerInfo SEQUENCE not found".into())
}

fn extract_signature_oid(fields: &[ASN1Block]) -> Result<OID, String> {
    if let Some(ASN1Block::Sequence(_, alg_fields)) = fields.get(4) {
        if let Some(ASN1Block::ObjectIdentifier(_, oid_val)) = alg_fields.get(0) {
            return Ok(oid_val.clone());
        }
    }
    Err("Signature algorithm OID missing".into())
}

fn extract_signature(fields: &[ASN1Block]) -> Result<String, String> {
    let block = fields
        .get(5)
        .ok_or_else(|| "Signature block not found".to_string())?;
    let bytes = match block {
        ASN1Block::OctetString(_, bs) => bs,
        ASN1Block::BitString(_, _, bs) => bs,
        other => return Err(format!("Unexpected signature block: {:?}", other)),
    };
    Ok(encode(bytes))
}

fn resolve_algorithm(oid_val: &OID, children: &[ASN1Block]) -> &'static str {
    use simple_asn1::oid;
    let rsa_enc = oid!(1, 2, 840, 113549, 1, 1, 1);
    let sha1_rsa = oid!(1, 2, 840, 113549, 1, 1, 5);
    let sha256_rsa = oid!(1, 2, 840, 113549, 1, 1, 11);
    let sha384_rsa = oid!(1, 2, 840, 113549, 1, 1, 12);
    let sha512_rsa = oid!(1, 2, 840, 113549, 1, 1, 13);
    let sha224_rsa = oid!(1, 2, 840, 113549, 1, 1, 14);

    // Try to extract digest OID from digestAlgorithms SET
    let digest_oid = if let Some(ASN1Block::Set(_, algs)) = children.get(1) {
        if let Some(ASN1Block::Sequence(_, items)) = algs.get(0) {
            if let Some(ASN1Block::ObjectIdentifier(_, d_oid)) = items.get(0) {
                Some(d_oid.clone())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Check combined signature OIDs first
    if *oid_val == sha256_rsa {
        "sha256WithRSAEncryption"
    } else if *oid_val == sha384_rsa {
        "sha384WithRSAEncryption"
    } else if *oid_val == sha512_rsa {
        "sha512WithRSAEncryption"
    } else if *oid_val == sha1_rsa {
        "sha1WithRSAEncryption"
    } else if *oid_val == sha224_rsa {
        "sha224WithRSAEncryption"
    } else if *oid_val == rsa_enc {
        // Infer from digestAlgorithms OID
        if let Some(d) = digest_oid {
            if d == oid!(2, 16, 840, 1, 101, 3, 4, 2, 1) {
                "sha256WithRSAEncryption"
            } else if d == oid!(2, 16, 840, 1, 101, 3, 4, 2, 2) {
                "sha384WithRSAEncryption"
            } else if d == oid!(2, 16, 840, 1, 101, 3, 4, 2, 3) {
                "sha512WithRSAEncryption"
            } else if d == oid!(1, 3, 14, 3, 2, 26) {
                "sha1WithRSAEncryption"
            } else if d == oid!(2, 16, 840, 1, 101, 3, 4, 2, 4) {
                "sha224WithRSAEncryption"
            } else {
                "rsaEncryption (unknown hash)"
            }
        } else {
            "rsaEncryption"
        }
    } else {
        "UnknownSignatureAlgorithm"
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        pkcs7_signature::{parse_signed_data, SignedDataInfo},
        signed_bytes_extractor::get_signature_der,
    };

    #[test]
    fn rsa_sha1_extraction() {
        let pdf_bytes = fs::read("../sample-pdfs/digitally_signed.pdf")
            .expect("Failed to read digitally_signed.pdf");

        let (der, signed_data) = get_signature_der(&pdf_bytes).expect("Failed to get signed data");

        let SignedDataInfo {
            signature: signature_hex,
            algorithm: signature_algorithm,
            modulus: modulus_hex,
            exponent,
        } = parse_signed_data(&der).expect("Failed to parse signed data");

        assert_eq!(signature_algorithm, "sha1WithRSAEncryption")
    }

    #[test]
    fn rsa_sha256_extraction() {
        // digital locked pdf
        let pdf_bytes = fs::read("../samples-private/pan-cert.pdf")
            .expect("Failed to read digitally_signed.pdf");

        let (der, signed_data) = get_signature_der(&pdf_bytes).expect("Failed to get signed data");
        let SignedDataInfo {
            signature: signature_hex,
            algorithm: signature_algorithm,
            modulus: modulus_hex,
            exponent,
        } = parse_signed_data(&der).expect("Failed to parse signed data");

        assert_eq!(signature_algorithm, "sha256WithRSAEncryption");
    }
}
