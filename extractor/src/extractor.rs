#[derive(Debug)]
struct PdfObject {
    id: String,                  // "7_0", "18_0" etc
    raw_stream: Option<Vec<u8>>, // Raw stream bytes -- compressed or plain
}

// Check whitespace
fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}

// Find next "<number> <number> obj" starting from position
fn find_obj_start(data: &[u8], start: usize) -> Option<usize> {
    let search = b" obj";
    memchr::memmem::find(&data[start..], search).map(|idx| start + idx)
}

// Parse object number and generation by walking backwards from idx
fn parse_obj_header(data: &[u8], idx: usize) -> (String, String) {
    if idx == 0 {
        return ("".to_string(), "".to_string());
    }
    let mut i = idx.saturating_sub(1);

    // Skip whitespace backwards
    while i > 0 && is_whitespace(data[i]) {
        i -= 1;
    }

    // Parse generation number backwards
    let gen_end = i;
    while i > 0 && (data[i] as char).is_ascii_digit() {
        i -= 1;
    }
    let gen_start = i + 1;
    let gen_num = std::str::from_utf8(&data[gen_start..=gen_end])
        .unwrap_or("")
        .to_string();

    // Skip whitespace backwards
    while i > 0 && is_whitespace(data[i]) {
        i -= 1;
    }

    // Parse object number backwards
    let obj_end = i;
    while i > 0 && (data[i] as char).is_ascii_digit() {
        i -= 1;
    }
    let obj_start = i + 1;
    let obj_num = std::str::from_utf8(&data[obj_start..=obj_end])
        .unwrap_or("")
        .to_string();

    (obj_num, gen_num)
}

// Find keyword ("stream", "endobj")
fn find_keyword(slice: &[u8], keyword: &[u8]) -> Option<usize> {
    memchr::memmem::find(slice, keyword)
}

// Clean the raw stream slice (skip \r\n)
fn clean_stream_bytes(slice: &[u8]) -> Vec<u8> {
    let mut stream_data = slice;
    if stream_data.starts_with(b"\r\n") {
        stream_data = &stream_data[2..];
    } else if stream_data.starts_with(b"\n") {
        stream_data = &stream_data[1..];
    }
    stream_data.to_vec()
}

fn parse_pdf(data: &[u8]) -> Vec<PdfObject> {
    let mut objects = Vec::new();
    let mut pos = 0;

    while let Some(idx) = find_obj_start(data, pos) {
        let (obj_num, gen_num) = parse_obj_header(data, idx);
        let id = format!("{}_{}", obj_num, gen_num);

        //find end of object
        if let Some(endobj_offset) = find_keyword(&data[idx..], b"endobj") {
            let object_slice = &data[idx..idx + endobj_offset];

            // see if this object has a stream…
            let raw_stream = if let Some(stream_offset) = find_keyword(object_slice, b"stream") {
                if let Some(endstream_offset) =
                    find_keyword(&object_slice[stream_offset..], b"endstream")
                {
                    let start = stream_offset + 6; // skip past "stream"
                    let end = stream_offset + endstream_offset;
                    Some(clean_stream_bytes(&object_slice[start..end]))
                } else {
                    None
                }
            } else {
                None
            };

            // only push *stream objects*
            if let Some(stream_bytes) = raw_stream {
                objects.push(PdfObject {
                    id,
                    raw_stream: Some(stream_bytes),
                });
            }

            pos = idx + endobj_offset + 6; // push "endobj"
        } else {
            break;
        }
    }

    objects
}

#[cfg(test)]
mod tests {
    use super::parse_pdf;
    use crate::decompress_to_utf8;
    use signature_validator::signed_bytes_extractor::get_signature_der;

    static SAMPLE_PDF_BYTES: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    static PAN_PDF_BYTES: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");

    #[test]
    fn chat1() {
        let (_, signed_bytes) =
            get_signature_der(&SAMPLE_PDF_BYTES).expect("Failed to get signed data");

        let res_map = parse_pdf(&signed_bytes);

        for obj in res_map.iter() {
            dbg!(&obj.id);
        }
    }

    #[test]
    fn chat2() {
        let (_, signed_bytes) =
            get_signature_der(&PAN_PDF_BYTES).expect("Failed to get signed data");

        let content_objs = parse_pdf(&signed_bytes);

        for obj in content_objs {
            let compressed = obj.raw_stream.as_ref().unwrap();
            let decompressed = decompress_to_utf8(compressed).expect("Decompression failed");
            println!("---- Object {} ----\n{}\n", obj.id, decompressed);
        }
    }
}
