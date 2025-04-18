use cryptographic_message_syntax::SignedData;
use lopdf::{Document, Object};

/// Verify the digital signature of a PDF from raw `pdf_bytes`.
///
/// Returns (is_signature_valid, optional_error_message)
///
/// - `true, None` → signature is valid.
/// - `false, Some(error)` → signature invalid or PDF malformed.
pub fn verify_pdf_signature(pdf_bytes: &[u8]) -> (bool, Option<&'static str>) {
    // Load the PDF document from memory
    let doc = match Document::load_mem(pdf_bytes) {
        Ok(doc) => doc,
        Err(_) => return (false, Some("Failed to load PDF from memory")),
    };

    // Find the signature dictionary (/Type /Sig)
    let mut signature_dict = None;
    for (_, obj) in doc.objects.iter() {
        if let Object::Dictionary(dict) = obj {
            if let Ok(Object::Name(name)) = dict.get(b"Type") {
                if name == b"Sig" {
                    signature_dict = Some(dict.clone());
                    break;
                }
            }
        }
    }
    let signature_dict = match signature_dict {
        Some(d) => d,
        None => return (false, Some("No signature dictionary found")),
    };

    // Extract ByteRange array
    let br_obj = match signature_dict.get(b"ByteRange") {
        Ok(obj) => obj,
        Err(_) => return (false, Some("No ByteRange found")),
    };
    let (_, br_obj) = match doc.dereference(br_obj) {
        Ok(res) => res,
        Err(_) => return (false, Some("Failed to dereference ByteRange")),
    };
    let br_array = match br_obj {
        Object::Array(arr) => arr,
        _ => return (false, Some("ByteRange is not an array")),
    };

    if br_array.len() < 4 || br_array.len() % 2 != 0 {
        return (false, Some("ByteRange length is invalid"));
    }

    // Collect signed byte ranges
    let mut ranges = vec![];
    for chunk in br_array.chunks(2) {
        let offset_obj = match doc.dereference(&chunk[0]) {
            Ok((_, obj)) => obj,
            Err(_) => return (false, Some("Failed to dereference ByteRange offsets")),
        };
        let len_obj = match doc.dereference(&chunk[1]) {
            Ok((_, obj)) => obj,
            Err(_) => return (false, Some("Failed to dereference ByteRange lengths")),
        };
        if let (Object::Integer(offset), Object::Integer(len)) = (offset_obj, len_obj) {
            ranges.push((*offset as usize, *len as usize));
        } else {
            return (false, Some("ByteRange entries are not integers"));
        }
    }

    // Reassemble signed content from memory
    let mut signed_bytes = Vec::with_capacity(ranges.iter().map(|(_, len)| *len).sum());
    for &(offset, len) in &ranges {
        if offset + len > pdf_bytes.len() {
            return (false, Some("ByteRange exceeds file size"));
        }
        signed_bytes.extend_from_slice(&pdf_bytes[offset..offset + len]);
    }

    // Extract and clean the signature contents
    let contents_obj = match signature_dict.get(b"Contents") {
        Ok(obj) => obj,
        Err(_) => return (false, Some("No Contents found")),
    };
    let (_, contents_obj) = match doc.dereference(contents_obj) {
        Ok(res) => res,
        Err(_) => return (false, Some("Failed to dereference Contents")),
    };
    let mut signature_bytes = match contents_obj {
        Object::String(data, _) => data.clone(),
        Object::Stream(stream) => stream.content.clone(),
        _ => return (false, Some("Contents is not a string or stream")),
    };

    // Remove trailing 0x00 padding
    while signature_bytes.last() == Some(&0) {
        signature_bytes.pop();
    }

    // Parse the PKCS#7 CMS signature
    let signed_data = match SignedData::parse_ber(&signature_bytes) {
        Ok(sd) => sd,
        Err(_) => return (false, Some("Failed to parse PKCS#7 signature")),
    };

    // Get the signer info
    let signer = match signed_data.signers().next() {
        Some(s) => s,
        None => return (false, Some("No SignerInfo found")),
    };

    // Verify document hash matches signer's message digest
    if signer
        .verify_message_digest_with_content(&signed_bytes)
        .is_err()
    {
        return (false, Some("Document hash mismatch"));
    }

    // Verify the signature itself
    if signer
        .verify_signature_with_signed_data(&signed_data)
        .is_err()
    {
        return (false, Some("Signature verification failed"));
    }

    // All good!
    (true, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_valid_signature() {
        let pdf_bytes = fs::read("/Users/vikasrushi/pdf-utils/sample-pdfs/digitally_signed.pdf")
            .expect("Failed to read PDF file");
        let (is_valid, message) = verify_pdf_signature(&pdf_bytes);
        assert!(is_valid, "{:?}", message);
    }

    #[test]
    fn test_digilocker_documents() {
        let pan_card_pdf = fs::read("/Users/vikasrushi/pdf-utils/samples-private/pan-cert.pdf")
            .expect("Failed to read PAN Card PDF");
        let bank_pdf = fs::read("/Users/vikasrushi/pdf-utils/samples-private/bank-cert.pdf")
            .expect("Failed to read Bank Certificate PDF");

        let (is_valid, message) = verify_pdf_signature(&pan_card_pdf);
        assert!(is_valid, "{:?}", message);

        let (is_valid, message) = verify_pdf_signature(&bank_pdf);
        assert!(is_valid, "{:?}", message);
    }
}
