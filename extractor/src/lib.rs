use memchr::memmem;
use miniz_oxide::inflate::decompress_to_vec_zlib;
use std::collections::HashMap;

const OBJ_KW: &[u8] = b" obj";
const STREAM_KW: &[u8] = b"stream";
const ENDSTREAM_KW: &[u8] = b"endstream";
const ENDOBJ_KW: &[u8] = b"endobj";

/// Skip metadata and *image* XObjects, but keep Form XObjects (where most text lives).
fn is_skippable(dict: &[u8]) -> bool {
    dict.windows(12).any(|w| w == b"/Type /Metadata")
        || dict.windows(14).any(|w| w == b"/Subtype /Image")
}

/// Extract all text-showing operators from a PDF byte slice.
/// Returns a map from object-generation IDs (e.g. "8_0") to the concatenated text found there.
pub fn extract_text_from_pdf(pdf_bytes: &[u8]) -> HashMap<String, String> {
    let mut texts = HashMap::new();
    let mut i = 0;
    let len = pdf_bytes.len();

    while i < len {
        // Look for the next " obj"
        if let Some(rel) = memmem::find(&pdf_bytes[i..], OBJ_KW) {
            let obj_pos = i + rel;

            // Back up to parse object ID
            if let Some(obj_id) = parse_object_id(&pdf_bytes[..obj_pos]) {
                // Slice until "endobj"
                if let Some(endobj_rel) = memmem::find(&pdf_bytes[obj_pos..], ENDOBJ_KW) {
                    let obj_block = &pdf_bytes[obj_pos..obj_pos + endobj_rel];

                    // Process stream if present
                    if let Some((dict, stream_slice)) = get_stream_and_dict(obj_block) {
                        if !is_skippable(dict) && dict.windows(12).any(|w| w == b"/FlateDecode") {
                            if let Ok(decompressed) = decompress_to_vec_zlib(stream_slice) {
                                let text = parse_content_stream(&decompressed);
                                if !text.is_empty() {
                                    texts.insert(obj_id.clone(), text);
                                }
                            }
                        }
                    }

                    i = obj_pos + endobj_rel + ENDOBJ_KW.len();
                    continue;
                }
            }
        }
        i += 1;
    }

    texts
}

/// Parse "num gen" before the " obj" to produce "num_gen".
fn parse_object_id(prefix: &[u8]) -> Option<String> {
    let mut j = prefix.len().saturating_sub(1);
    while j > 0 && prefix[j].is_ascii_whitespace() {
        j -= 1;
    }
    // gen end -> start
    let mut gen_end = j;
    while gen_end > 0 && (prefix[gen_end] as char).is_ascii_digit() {
        gen_end -= 1;
    }
    let gen_start = gen_end + 1;

    // skip space before gen
    let mut num_end = gen_end;
    while num_end > 0 && prefix[num_end].is_ascii_whitespace() {
        num_end -= 1;
    }
    // num start
    let mut num_start = num_end;
    while num_start > 0 && (prefix[num_start] as char).is_ascii_digit() {
        num_start -= 1;
    }
    if num_start > 0 {
        num_start += 1;
    }

    let num = std::str::from_utf8(&prefix[num_start..=num_end]).ok()?;
    let gen = std::str::from_utf8(&prefix[gen_start..=j]).ok()?;
    Some(format!("{}_{}", num, gen))
}

/// From the object block, return (dict_bytes, compressed_data_slice).
fn get_stream_and_dict(obj: &[u8]) -> Option<(&[u8], &[u8])> {
    let stream_pos = memmem::find(obj, STREAM_KW)?;
    let endstream_rel = memmem::find(&obj[stream_pos..], ENDSTREAM_KW)?;

    let dict = &obj[..stream_pos];
    let mut data_start = stream_pos + STREAM_KW.len();
    if obj.get(data_start) == Some(&b'\r') {
        data_start += 1;
    }
    if obj.get(data_start) == Some(&b'\n') {
        data_start += 1;
    }
    let data_end = stream_pos + endstream_rel;

    Some((dict, &obj[data_start..data_end]))
}

/// Scan decompressed content for text operators and concatenate.
fn parse_content_stream(content: &[u8]) -> String {
    let mut out = String::new();
    let mut k = 0;

    while k < content.len() {
        match content[k] {
            b'(' => {
                // Literal string
                let mut depth = 1;
                let mut k0 = k + 1;
                let mut buf = Vec::new();
                while k0 < content.len() && depth > 0 {
                    match content[k0] {
                        b'\\' => {
                            k0 += 1;
                            if k0 >= content.len() {
                                break;
                            }
                            match content[k0] {
                                b'n' => buf.push(b'\n'),
                                b'r' => buf.push(b'\r'),
                                b't' => buf.push(b'\t'),
                                b'b' => buf.push(0x08),
                                b'f' => buf.push(0x0C),
                                b'(' => buf.push(b'('),
                                b')' => buf.push(b')'),
                                b'\\' => buf.push(b'\\'),
                                c if (c as char).is_digit(10) => {
                                    // octal
                                    let mut oct = 0;
                                    let mut count = 0;
                                    let mut oct_k = k0;
                                    while oct_k < content.len() && count < 3 {
                                        if let Some(d) = (content[oct_k] as char).to_digit(8) {
                                            oct = (oct * 8) + d;
                                            oct_k += 1;
                                            count += 1;
                                        } else {
                                            break;
                                        }
                                    }
                                    buf.push(oct as u8);
                                    k0 = oct_k - 1;
                                }
                                _ => {}
                            }
                        }
                        b'(' => {
                            depth += 1;
                            buf.push(b'(');
                        }
                        b')' => {
                            depth -= 1;
                            if depth > 0 {
                                buf.push(b')');
                            }
                        }
                        c => buf.push(c),
                    }
                    k0 += 1;
                }
                let literal = String::from_utf8_lossy(&buf);
                k = k0;
                // Skip whitespace
                while k < content.len() && content[k].is_ascii_whitespace() {
                    k += 1;
                }
                // Check following operator
                if content.get(k) == Some(&b'T') && content.get(k + 1) == Some(&b'j') {
                    out.push_str(&literal);
                    k += 2;
                } else if content.get(k) == Some(&b'\'') {
                    out.push_str(&literal);
                    out.push('\n');
                    k += 1;
                } else if content.get(k) == Some(&b'"') {
                    out.push_str(&literal);
                    out.push('\n');
                    k += 1;
                }
            }

            b'<' if content.get(k + 1) != Some(&b'<') => {
                // Hex string
                let mut buf = Vec::new();
                k += 1;
                while k < content.len() && content[k] != b'>' {
                    if !content[k].is_ascii_whitespace() {
                        buf.push(content[k]);
                    }
                    k += 1;
                }
                if let Ok(hex_str) = std::str::from_utf8(&buf) {
                    let mut bytes = Vec::new();
                    let hex_bytes = if hex_str.len() % 2 == 1 {
                        format!("{}0", hex_str)
                    } else {
                        hex_str.to_string()
                    };
                    for pair in hex_bytes.as_bytes().chunks(2) {
                        if let Ok(byte) = u8::from_str_radix(
                            &format!("{}{}", pair[0] as char, pair[1] as char),
                            16,
                        ) {
                            bytes.push(byte);
                        }
                    }
                    if let Ok(text) = String::from_utf8(bytes) {
                        while k < content.len() && content[k].is_ascii_whitespace() {
                            k += 1;
                        }
                        if content.get(k) == Some(&b'T') && content.get(k + 1) == Some(&b'j') {
                            out.push_str(&text);
                            k += 2;
                        } else if content.get(k) == Some(&b'\'') {
                            out.push_str(&text);
                            out.push('\n');
                            k += 1;
                        } else if content.get(k) == Some(&b'"') {
                            out.push_str(&text);
                            out.push('\n');
                            k += 1;
                        }
                    }
                }
            }

            b'[' => {
                // TJ array
                let mut arr_str = String::new();
                k += 1;
                while k < content.len() && content[k] != b']' {
                    if content[k] == b'(' {
                        // extract sub-literal
                        let mut depth = 1;
                        let mut k0 = k + 1;
                        let mut buf = Vec::new();
                        while k0 < content.len() && depth > 0 {
                            match content[k0] {
                                b'\\' => {
                                    k0 += 1;
                                    if k0 >= content.len() {
                                        break;
                                    }
                                    match content[k0] {
                                        b'n' => buf.push(b'\n'),
                                        b'r' => buf.push(b'\r'),
                                        b't' => buf.push(b'\t'),
                                        b'b' => buf.push(0x08),
                                        b'f' => buf.push(0x0C),
                                        b'(' => buf.push(b'('),
                                        b')' => buf.push(b')'),
                                        b'\\' => buf.push(b'\\'),
                                        c if (c as char).is_digit(10) => {
                                            let mut oct = 0;
                                            let mut count = 0;
                                            let mut oct_k = k0;
                                            while oct_k < content.len() && count < 3 {
                                                if let Some(d) =
                                                    (content[oct_k] as char).to_digit(8)
                                                {
                                                    oct = (oct * 8) + d;
                                                    oct_k += 1;
                                                    count += 1;
                                                } else {
                                                    break;
                                                }
                                            }
                                            buf.push(oct as u8);
                                            k0 = oct_k - 1;
                                        }
                                        _ => {}
                                    }
                                }
                                b'(' => {
                                    depth += 1;
                                    buf.push(b'(');
                                }
                                b')' => {
                                    depth -= 1;
                                    if depth > 0 {
                                        buf.push(b')');
                                    }
                                }
                                c => buf.push(c),
                            }
                            k0 += 1;
                        }
                        if let Ok(s) = String::from_utf8(buf) {
                            arr_str.push_str(&s);
                        }
                        k = k0;
                    } else if content[k].is_ascii_digit()
                        || content[k] == b'-'
                        || content[k] == b'.'
                    {
                        while k < content.len()
                            && ((content[k] as char).is_digit(10)
                                || content[k] == b'-'
                                || content[k] == b'.')
                        {
                            k += 1;
                        }
                    } else {
                        k += 1;
                    }
                }
                if k < content.len() && content[k] == b']' {
                    k += 1;
                }
                while k < content.len() && content[k].is_ascii_whitespace() {
                    k += 1;
                }
                if content.get(k) == Some(&b'T') && content.get(k + 1) == Some(&b'J') {
                    out.push_str(&arr_str);
                    k += 2;
                }
            }

            // New‐line operators
            b'T' if content.get(k + 1) == Some(&b'd') => {
                out.push('\n');
                k += 2;
            }
            b'T' if content.get(k + 1) == Some(&b'*') => {
                out.push('\n');
                k += 2;
            }

            // Otherwise skip one byte
            _ => {
                k += 1;
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    static PAN_PDF: &[u8] = include_bytes!("../../samples-private/output-new.pdf");
    static SAMPLE_PDF: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    static BANK: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");

    #[test]
    fn test_sample_pdf_extraction() {
        let texts = extract_text_from_pdf(&SAMPLE_PDF[..]);
        for (id, text) in &texts {
            println!("Object ID: {}", id);
            println!("Text: {}", text);
        }
        dbg!(texts.len());
        assert!(!texts.is_empty());
    }
}
