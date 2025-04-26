use std::error::Error;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use sha2::{Digest, Sha256, Sha384, Sha512};
use simple_asn1::{from_der, oid, ASN1Block, ASN1Class};

use crate::SignatureAlgorithm;

pub struct VerifierParams {
    pub modulus: Vec<u8>,
    pub exponent: BigUint,
    pub signature: Vec<u8>,
    pub signed_attr_digest: Vec<u8>,
    pub algorithm: SignatureAlgorithm,
    pub signed_data_message_digest: Vec<u8>,
}

pub fn parse_signed_data(der_bytes: &[u8]) -> Result<VerifierParams, String> {
    let blocks = from_der(der_bytes).map_err(|e| format!("DER parse error: {}", e))?;

    let content_info = extract_content_info(&blocks)?;
    let signed_children = extract_signed_children(content_info)?;
    let (signature, signer_serial, digest_bytes, signed_algo, expected_message_digest) =
        get_signature(signed_children.clone())?;

    let (modulus_bytes, exponent_big) =
        extract_pubkey_components(&signed_children, &signer_serial)?;

    Ok(VerifierParams {
        modulus: modulus_bytes,
        exponent: exponent_big,
        signature,
        signed_attr_digest: digest_bytes,
        algorithm: signed_algo,
        signed_data_message_digest: expected_message_digest,
    })
}

fn get_signature(
    signed_data_seq: Vec<ASN1Block>,
) -> Result<(Vec<u8>, BigUint, Vec<u8>, SignatureAlgorithm, Vec<u8>), String> {
    // first last item of SignedData is signerInfos
    let signer_info = match &signed_data_seq.last() {
        Some(ASN1Block::Set(_, items)) => items,
        _ => return Err("Expected SignerInfo in SignedData".into()),
    };

    // SignerInfo ::= SEQUENCE {
    // version
    // issuerAndSerialNumber
    // digestAlgorithm
    // signedAttributes
    // signatureAlgorithm
    // signature
    // }

    let signer_info = match &signer_info[0] {
        ASN1Block::Sequence(_, items) => items,
        _ => return Err("Expected SignerInfo in SignedData".into()),
    };

    // issuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }
    let (_, signer_serial) = match &signer_info[1] {
        ASN1Block::Sequence(_, parts) if parts.len() == 2 => {
            // Extract issuer (a SEQUENCE of RDNs)
            let issuer = match &parts[0] {
                ASN1Block::Sequence(_, seq) => seq.clone(),
                other => return Err(format!("Expected issuer SEQUENCE, got {:?}", other).into()),
            };

            // Extract serialNumber and convert to BigUint
            let serial = match &parts[1] {
                ASN1Block::Integer(_, big_int) => {
                    BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
                }
                other => {
                    return Err(format!("Expected serialNumber INTEGER, got {:?}", other).into())
                }
            };

            (issuer, serial)
        }
        other => {
            return Err(format!("Expected issuerAndSerialNumber SEQUENCE, got {:?}", other).into())
        }
    };

    let digest_oid = if let ASN1Block::Sequence(_, items) = &signer_info[2] {
        if let ASN1Block::ObjectIdentifier(_, oid) = &items[0] {
            oid.clone()
        } else {
            return Err("Invalid digestAlgorithm in SignerInfo".into());
        }
    } else {
        return Err("Digest algorithm missing".into());
    };

    let mut signed_attrs_der: Option<Vec<u8>> = None;
    for block in signer_info {
        match block {
            // Match the IMPLICIT [0] block
            ASN1Block::Unknown(ASN1Class::ContextSpecific, true, _len, tag_no, content) => {
                match tag_no == &BigUint::from(0u8) {
                    true => {
                        // Build universal SET tag + length
                        let mut out = Vec::with_capacity(content.len() + 4);
                        out.push(0x31); // SET

                        let len = content.len();
                        if len < 128 {
                            out.push(len as u8);
                        } else if len <= 0xFF {
                            out.push(0x81);
                            out.push(len as u8);
                        } else {
                            out.push(0x82);
                            out.push((len >> 8) as u8);
                            out.push((len & 0xFF) as u8);
                        }

                        out.extend_from_slice(content);

                        signed_attrs_der = Some(out);
                        break;
                    }
                    false => {
                        continue;
                    }
                }
            }

            // All other blocks: skip
            _ => continue,
        }
    }

    let signed_attrs_der = match signed_attrs_der {
        Some(v) => v,
        None => return Err("signedAttrs [0] not found".into()),
    };

    let signed_algo: SignatureAlgorithm;
    // Compute the hash of the DER-encoded signedAttrs according to digest_oid
    let digest_bytes = match digest_oid {
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 1) => {
            // SHA-256
            signed_algo = SignatureAlgorithm::Sha256WithRsaEncryption;
            let mut h = Sha256::new();
            h.update(&signed_attrs_der);
            h.finalize().to_vec()
        }
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 2) => {
            // SHA-384
            signed_algo = SignatureAlgorithm::Sha384WithRsaEncryption;
            let mut h = Sha384::new();
            h.update(&signed_attrs_der);
            h.finalize().to_vec()
        }
        oid if oid == oid!(2, 16, 840, 1, 101, 3, 4, 2, 3) => {
            // SHA-512
            signed_algo = SignatureAlgorithm::Sha512WithRsaEncryption;
            let mut h = Sha512::new();
            h.update(&signed_attrs_der);
            h.finalize().to_vec()
        }
        oid if oid == oid!(1, 3, 14, 3, 2, 26) => {
            // SHA-1
            signed_algo = SignatureAlgorithm::Sha1WithRsaEncryption;
            let mut h = sha1::Sha1::new();
            h.update(&signed_attrs_der);
            h.finalize().to_vec()
        }
        _ => return Err(format!("Unsupported digest OID").into()),
    };

    let signed_attrs =
        from_der(&signed_attrs_der).map_err(|e| format!("signedAttrs parse error: {}", e))?;

    let signed_data_message_digest = extract_message_digest(&signed_attrs)
        .map_err(|e| format!("Failed to get messageDigest: {}", e))?;
    let sig_index = if digest_bytes.is_empty() { 4 } else { 5 };
    let signature_bytes = if let ASN1Block::OctetString(_, s) = &signer_info[sig_index] {
        s.clone()
    } else {
        return Err("EncryptedDigest (signature) not found".into());
    };
    Ok((
        signature_bytes,
        signer_serial,
        digest_bytes,
        signed_algo,
        signed_data_message_digest,
    ))
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

pub fn extract_signed_children(children: &[ASN1Block]) -> Result<Vec<ASN1Block>, String> {
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

pub fn extract_pubkey_components(
    signed_data_seq: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Result<(Vec<u8>, BigUint), String> {
    // Find the certificates [0] IMPLICIT (may be Explicit or Unknown in parsing)
    let certs_block = signed_data_seq.iter().find(|block| match block {
        ASN1Block::Explicit(ASN1Class::ContextSpecific, _, tag, _) => {
            tag == &simple_asn1::BigUint::from_usize(0).unwrap()
        }
        ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, tag, _) => {
            tag == &simple_asn1::BigUint::from_usize(0).unwrap()
        }
        _ => false,
    });

    // Extract the Vec<ASN1Block> containing the individual certificate SEQUENCEs
    let certificates: Vec<ASN1Block> = match certs_block {
        Some(cert_block) => match cert_block {
            // 1) Implicit [0] IMPLICIT SET/SEQUENCE OF Certificate
            ASN1Block::Unknown(ASN1Class::ContextSpecific, _, _, tag, data)
                if tag == &BigUint::from(0u8) =>
            {
                // Parse the inner content which should be the SEQUENCEs/SET
                let parsed_inner =
                    from_der(data).map_err(|e| format!("Cert wrapper parse error: {}", e))?;
                // Match on the entire parsed_inner
                match parsed_inner.as_slice() {
                    // a) single SET of certificates
                    [ASN1Block::Set(_, items)] => items.clone(),

                    // b) single SEQUENCE of certificates
                    [ASN1Block::Sequence(_, items)] => items.clone(),

                    // c) multiple back-to-back SEQUENCEs (each a cert)
                    seqs if seqs.iter().all(|b| matches!(b, ASN1Block::Sequence(_, _))) => {
                        seqs.to_vec()
                    }

                    other => {
                        return Err(format!(
                            "Unexpected structure inside implicit certificate block: {:?}",
                            other
                        )
                        .into())
                    }
                }
            }

            // 2) Explicit [0] EXPLICIT SET/SEQUENCE OF Certificate
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, tag, inner)
                if tag == &BigUint::from(0u8) =>
            {
                match inner.as_ref() {
                    ASN1Block::Set(_, certs) => certs.clone(),

                    ASN1Block::Sequence(tag, fields) => {
                        vec![ASN1Block::Sequence(*tag, fields.clone())]
                    }

                    other => {
                        return Err(format!(
                            "Expected SET or SEQUENCE inside Explicit certificate block, got {:?}",
                            other
                        )
                        .into())
                    }
                }
            }

            // 3) bare SET OF Certificate
            ASN1Block::Set(_, items)
                if items.iter().all(|i| matches!(i, ASN1Block::Sequence(_, _))) =>
            {
                items.clone()
            }

            other => return Err(format!("Unexpected certificates block type: {:?}", other).into()),
        },
        None => Vec::new(),
    };

    // tbsCertificate (child[0])
    let tbs_fields = get_correct_tbs(&certificates, &signed_serial_number);

    let tbs_fields = match tbs_fields {
        Ok(fields) => fields,
        Err(e) => return Err(format!("Failed to get correct tbsCertificate: {}", e).into()),
    };

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

fn get_correct_tbs(
    certificates: &Vec<ASN1Block>,
    signed_serial_number: &BigUint,
) -> Result<Vec<ASN1Block>, Box<dyn Error>> {
    // Iterate through each cert until we find the one with the matching serial
    for certificate in certificates {
        // 1) Ensure the certificate is a SEQUENCE
        let cert_fields = if let ASN1Block::Sequence(_, fields) = certificate {
            fields
        } else {
            return Err("Certificate not a SEQUENCE".into());
        };

        // 2) Unwrap tbsCertificate: either an explicit [0] wrapper or a direct SEQUENCE
        let tbs_fields = match &cert_fields[0] {
            ASN1Block::Explicit(ASN1Class::ContextSpecific, _, _, _) => cert_fields.clone(),
            ASN1Block::Sequence(_, seq) => seq.clone(),
            _ => return Err("tbsCertificate not found".into()),
        };

        // 3) Extract the serialNumber (second field of tbsCertificate)
        let serial_number = if let ASN1Block::Integer(_, big_int) = &tbs_fields[1] {
            BigUint::from_bytes_be(&big_int.to_signed_bytes_be())
        } else {
            return Err("Serial number not found".into());
        };

        // 4) If it matches, return the tbsCertificate fields immediately
        if serial_number == *signed_serial_number {
            return Ok(tbs_fields);
        }
    }

    // If we never found a match, that's an error
    Err("No matching certificate found".into())
}

/// find and return the messageDigest OCTET STRING bytes.
fn extract_message_digest(attrs: &[ASN1Block]) -> Result<Vec<u8>, String> {
    // 1) If there's exactly one block and it's a SET, unwrap it to get at the SEQUENCEs.
    let candidates: &[ASN1Block] = if attrs.len() == 1 {
        if let ASN1Block::Set(_, inner) = &attrs[0] {
            inner.as_slice()
        } else {
            attrs
        }
    } else {
        attrs
    };

    // 2) Now each `attr` should be a Sequence([OID, Set([OctetString, …])])
    for attr in candidates {
        if let ASN1Block::Sequence(_, items) = attr {
            // items[0] = OID, items[1] = Set(_)
            if let ASN1Block::ObjectIdentifier(_, oid) = &items[0] {
                if *oid == oid!(1, 2, 840, 113549, 1, 9, 4) {
                    // pull the inner Set
                    if let ASN1Block::Set(_, inner_vals) = &items[1] {
                        // expect the first value to be an OctetString
                        if let ASN1Block::OctetString(_, data) = &inner_vals[0] {
                            return Ok(data.clone());
                        } else {
                            return Err("messageDigest value not an OctetString".into());
                        }
                    } else {
                        return Err("messageDigest missing inner Set".into());
                    }
                }
            }
        }
    }

    Err("messageDigest attribute (OID 1.2.840.113549.1.9.4) not found".into())
}
