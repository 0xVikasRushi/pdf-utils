use std::str;

pub fn get_signature_der(pdf_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    // Step 1: Find /ByteRange [
    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or("ByteRange not found")?;

    // Step 2: Find [ and ] after /ByteRange
    let start_bracket = pdf_bytes[br_pos..]
        .iter()
        .position(|&b| b == b'[')
        .ok_or("ByteRange [ not found")?
        + br_pos
        + 1;

    let end_bracket = pdf_bytes[start_bracket..]
        .iter()
        .position(|&b| b == b']')
        .ok_or("ByteRange ] not found")?
        + start_bracket;

    let br_slice = &pdf_bytes[start_bracket..end_bracket];

    // Step 3: Parse 4 numbers inside ByteRange
    let mut nums = [0usize; 4];
    let mut current = 0usize;
    let mut idx = 0;
    let mut in_number = false;

    for &b in br_slice {
        if b.is_ascii_digit() {
            in_number = true;
            current = current * 10 + (b - b'0') as usize;
        } else if in_number {
            if idx >= 4 {
                break;
            }
            nums[idx] = current;
            idx += 1;
            current = 0;
            in_number = false;
        }
    }
    if in_number && idx < 4 {
        nums[idx] = current;
        idx += 1;
    }

    if idx != 4 {
        return Err("Expected exactly 4 numbers inside ByteRange");
    }

    let [offset1, len1, offset2, len2] = nums;

    // Step 4: Basic boundary checks
    if offset1 + len1 > pdf_bytes.len() || offset2 + len2 > pdf_bytes.len() {
        return Err("ByteRange values out of bounds");
    }

    // Step 5: Reconstruct signed data
    let mut signed_data = Vec::with_capacity(len1 + len2);
    signed_data.extend_from_slice(&pdf_bytes[offset1..offset1 + len1]);
    signed_data.extend_from_slice(&pdf_bytes[offset2..offset2 + len2]);

    // Step 6: Find /Contents
    // Extract hex data as before
    let br_pos = pdf_bytes
        .windows(b"/ByteRange".len())
        .position(|w| w == b"/ByteRange")
        .ok_or("ByteRange not found")?;

    let contents_marker = b"/Contents";
    let contents_pos = pdf_bytes[br_pos..]
        .windows(contents_marker.len())
        .position(|w| w == contents_marker)
        .ok_or("Contents not found after ByteRange")?
        + br_pos;

    let start = pdf_bytes[contents_pos..]
        .iter()
        .position(|&b| b == b'<')
        .ok_or("Start '<' not found after Contents")?
        + contents_pos
        + 1;

    let end = pdf_bytes[start..]
        .iter()
        .position(|&b| b == b'>')
        .ok_or("End '>' not found after Contents")?
        + start;

    let hex_data = &pdf_bytes[start..end];
    let mut signature_der = Vec::with_capacity(hex_data.len() / 2);
    let mut byte = 0_u8;
    for (i, &h) in hex_data.iter().enumerate() {
        let val = match h {
            b'0'..=b'9' => h - b'0',
            b'A'..=b'F' => h - b'A' + 10,
            b'a'..=b'f' => h - b'a' + 10,
            _ => return Err("Contents hex parse error"),
        };
        if i % 2 == 0 {
            byte = val << 4;
        } else {
            byte |= val;
            signature_der.push(byte);
        }
    }
    while let Some(&0) = signature_der.last() {
        signature_der.pop();
    }

    Ok((signature_der, signed_data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_valid_signature() {
        let pdf_bytes =
            fs::read("../sample-pdfs/digitally_signed.pdf").expect("Failed to read PDF file");
        let (signature_der, _) = get_signature_der(&pdf_bytes).expect("Failed to get signed data");

        let expected_signature_bytes = fs::read("../sample-pdfs/digitally_signed_ber.txt")
            .expect("Failed to read expected signature DER file");
        let expected_signature = str::from_utf8(&expected_signature_bytes)
            .expect("Failed to convert signature DER to UTF-8")
            .trim()
            .to_string();

        assert_eq!(expected_signature, hex::encode(&signature_der))
    }
}
