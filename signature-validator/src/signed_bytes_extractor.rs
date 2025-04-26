use std::str;

pub fn get_signature_der(pdf_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // 1) Locate the /ByteRange[...] and extract the inner ASCII slice
    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or("ByteRange not found")?;
    let br_start = pdf_bytes[br_pos..]
        .iter()
        .position(|&b| b == b'[')
        .ok_or("ByteRange '[' not found")?
        + br_pos
        + 1;
    let br_end = pdf_bytes[br_start..]
        .iter()
        .position(|&b| b == b']')
        .ok_or("ByteRange ']' not found")?
        + br_start;
    let br_str =
        str::from_utf8(&pdf_bytes[br_start..br_end]).map_err(|_| "Invalid ByteRange data")?;

    // 2) Parse exactly four usize values
    let nums: Vec<usize> = br_str
        .split_whitespace()
        .filter_map(|s| s.parse().ok())
        .take(4)
        .collect();
    if nums.len() != 4 {
        return Err("Expected exactly 4 numbers inside ByteRange");
    }
    let [offset1, len1, offset2, len2] = [nums[0], nums[1], nums[2], nums[3]];

    // 3) Boundary check
    if offset1 + len1 > pdf_bytes.len() || offset2 + len2 > pdf_bytes.len() {
        return Err("ByteRange values out of bounds");
    }

    // 4) Reconstruct the signed_data
    let mut signed_data = Vec::with_capacity(len1 + len2);
    signed_data.extend_from_slice(&pdf_bytes[offset1..offset1 + len1]);
    signed_data.extend_from_slice(&pdf_bytes[offset2..offset2 + len2]);

    // 5) Locate the /Contents<...> hex blob
    let contents_pos = pdf_bytes[br_pos..]
        .windows(b"/Contents".len())
        .position(|w| w == b"/Contents")
        .ok_or("Contents not found after ByteRange")?
        + br_pos;
    let hex_start = pdf_bytes[contents_pos..]
        .iter()
        .position(|&b| b == b'<')
        .ok_or("Start '<' not found after Contents")?
        + contents_pos
        + 1;
    let hex_end = pdf_bytes[hex_start..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or("End '>' not found after Contents")?
        + hex_start;

    // 6) Decode the hex into DER bytes, stripping any trailing zero padding
    let hex_str =
        str::from_utf8(&pdf_bytes[hex_start..hex_end]).map_err(|_| "Invalid hex in Contents")?;
    let mut signature_der = hex::decode(hex_str).map_err(|_| "Contents hex parse error")?;
    while signature_der.last() == Some(&0) {
        signature_der.pop();
    }

    Ok((signature_der, signed_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Digest;
    use sha2::Sha256;

    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    static BANK_PDF_BYTES: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");
    static PAN_PDF_BYTES: &[u8] = include_bytes!("../../samples-private/pan-cert.pdf");
    static EXPECTED_SIG_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed_ber.txt");
    #[test]
    fn sample_pdf_signature_and_hash() {
        let (signature_der, signed_data) =
            get_signature_der(&SAMPLE_PDF_BYTES).expect("Failed to get signed data");

        let expected_signature = std::str::from_utf8(&EXPECTED_SIG_BYTES)
            .expect("Failed to convert signature DER to UTF-8")
            .trim()
            .to_string();

        let mut hasher = sha1::Sha1::new();
        hasher.update(&signed_data);
        let hash = hasher.finalize();

        assert_eq!(
            hex::encode(&hash),
            "3f0047e6cb5b9bb089254b20d174445c3ba4f513"
        );

        assert_eq!(expected_signature, hex::encode(&signature_der));
    }

    #[test]
    fn bank_pdf_sha256_hash() {
        let (_, signed_data) =
            get_signature_der(BANK_PDF_BYTES).expect("failed to extract signed data");

        let mut hasher = Sha256::new();
        hasher.update(&signed_data);
        let digest = hasher.finalize();

        assert_eq!(
            hex::encode(digest),
            "8f4a45720f3076fe51cc4fd1b5b23387fa6bbfb463262e6095e3af62a039dea1"
        );
    }

    #[test]
    fn pan_pdf_sha256_hash() {
        let (_, signed_data) =
            get_signature_der(PAN_PDF_BYTES).expect("failed to extract signed data");

        let mut hasher = Sha256::new();
        hasher.update(&signed_data);
        let digest = hasher.finalize();

        assert_eq!(
            hex::encode(digest),
            "a6c81c2d89d36a174273a4faa06fcfc91db574f572cfdf3a6518d08fb4eb4155"
        );
    }
}
