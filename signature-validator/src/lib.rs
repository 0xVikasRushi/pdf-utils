use cryptographic_message_syntax::SignedData;
use lopdf::{Document, Object};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Verify the digital signature of a PDF at `pdf_path`.
///
/// Returns (is_signature_valid, optional_error_message)
///
/// - `true, None` → signature is valid.
/// - `false, Some(error)` → signature invalid or PDF malformed.
pub fn verify_pdf_signature(pdf_path: &str) -> (bool, Option<&'static str>) {
    //  Load the PDF document
    let doc = match Document::load(pdf_path) {
        Ok(doc) => doc,
        Err(_) => return (false, Some("Failed to load PDF")),
    };

    //  Find the signature dictionary (/Type /Sig)
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

    //  Extract the ByteRange array
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

    // Validate ByteRange structure
    if br_array.len() < 4 || br_array.len() % 2 != 0 {
        return (false, Some("ByteRange length is invalid"));
    }

    // Collect all signed byte ranges
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
            ranges.push((*offset as u64, *len as u64));
        } else {
            return (false, Some("ByteRange entries are not integers"));
        }
    }

    // Reassemble signed bytes by reading file slices
    let mut file = match File::open(pdf_path) {
        Ok(f) => f,
        Err(_) => return (false, Some("Failed to open PDF file")),
    };
    let mut signed_bytes = Vec::with_capacity(ranges.iter().map(|(_, len)| *len as usize).sum());
    for &(offset, len) in &ranges {
        if file.seek(SeekFrom::Start(offset)).is_err() {
            return (false, Some("Failed to seek in PDF file"));
        }
        let mut buffer = vec![0; len as usize];
        if file.read_exact(&mut buffer).is_err() {
            return (false, Some("Failed to read PDF file"));
        }
        signed_bytes.extend_from_slice(&buffer);
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

    // all good!
    (true, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pan_card_pdf() {
        let pdf_path = "/Users/vikasrushi/pdf-utils/sample-pdfs/pan-cert.pdf";
        let (is_valid, message) = verify_pdf_signature(pdf_path);
        assert!(is_valid, "{:?}", message);
    }

    #[test]
    fn test_bank_cert_pdf() {
        let pdf_path = "/Users/vikasrushi/pdf-utils/sample-pdfs/bank-cert.pdf";
        let (is_valid, message) = verify_pdf_signature(pdf_path);
        assert!(is_valid, "{:?}", message);
    }
}
