pub fn get_signed_data(pdf_bytes: &[u8]) -> Result<(Vec<u8>), &'static str> {
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

    // Step 5: Reconstruct signed data (optional)
    let mut signed_data = Vec::with_capacity(len1 + len2);
    signed_data.extend_from_slice(&pdf_bytes[offset1..offset1 + len1]);
    signed_data.extend_from_slice(&pdf_bytes[offset2..offset2 + len2]);

    Ok(signed_data)
}
