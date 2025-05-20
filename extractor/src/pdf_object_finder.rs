use memchr::memmem;
use miniz_oxide::inflate::decompress_to_vec_zlib;

// Keywords used to identify parts of PDF objects and streams
const OBJ_KW: &[u8] = b"obj";
const STREAM_KW: &[u8] = b"stream";
const ENDSTREAM_KW: &[u8] = b"endstream";
const ENDOBJ_KW: &[u8] = b"endobj";

#[derive(Debug, Clone)]
pub struct FoundStreamInfo {
    pub object_id: String,
    pub dictionary_bytes: Vec<u8>,
    pub decompressed_stream_data: Vec<u8>,
}

/// Parses the object ID (e.g., "10 0") from the bytes preceding an "obj" keyword.

fn parse_object_id(prefix: &[u8]) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }

    // Find Generation Number (working backwards)
    let mut gen_end_idx = prefix.len() - 1;
    while gen_end_idx > 0
        && prefix
            .get(gen_end_idx)
            .map_or(false, |c| c.is_ascii_whitespace())
    {
        gen_end_idx -= 1;
    }
    // gen_end_idx now points to the last non-whitespace char, assumed to be the end of the gen number.

    if !prefix
        .get(gen_end_idx)
        .map_or(false, |c| c.is_ascii_digit())
    {
        return None;
    }

    let mut gen_start_idx = gen_end_idx;
    while gen_start_idx > 0
        && prefix
            .get(gen_start_idx - 1)
            .map_or(false, |c| c.is_ascii_digit())
    {
        gen_start_idx -= 1;
    }

    if gen_start_idx == 0 {
        return None;
    }
    let mut obj_end_idx = gen_start_idx - 1;
    while obj_end_idx > 0
        && prefix
            .get(obj_end_idx)
            .map_or(false, |c| c.is_ascii_whitespace())
    {
        obj_end_idx -= 1;
    }

    if !prefix
        .get(obj_end_idx)
        .map_or(false, |c| c.is_ascii_digit())
    {
        return None;
    }

    let mut obj_start_idx = obj_end_idx;
    while obj_start_idx > 0
        && prefix
            .get(obj_start_idx - 1)
            .map_or(false, |c| c.is_ascii_digit())
    {
        obj_start_idx -= 1;
    }

    let num_slice = prefix.get(obj_start_idx..=obj_end_idx)?;
    let gen_slice = prefix.get(gen_start_idx..=gen_end_idx)?;

    let num_str = std::str::from_utf8(num_slice).ok()?;
    let gen_str = std::str::from_utf8(gen_slice).ok()?;

    if num_str.is_empty() || gen_str.is_empty() {
        return None;
    }

    Some(format!("{}_{}", num_str, gen_str))
}

/// Extracts the dictionary and the raw stream data from an object's content block.
/// `obj_content_block` is the data between "X Y obj" (and any following whitespace) and "endobj".
fn get_stream_and_dict(obj_content_block: &[u8]) -> Option<(&[u8], &[u8])> {
    let stream_key_pos = memmem::find(obj_content_block, STREAM_KW)?;
    let dict_bytes = obj_content_block.get(..stream_key_pos)?;

    // Data starts after "stream" and the following EOL (CRLF, LF, or CR).
    let mut data_start_offset = stream_key_pos + STREAM_KW.len();
    if obj_content_block.get(data_start_offset) == Some(&b'\r') {
        data_start_offset += 1;
        if obj_content_block.get(data_start_offset) == Some(&b'\n') {
            // Handle CRLF
            data_start_offset += 1;
        }
    } else if obj_content_block.get(data_start_offset) == Some(&b'\n') {
        // Handle LF
        data_start_offset += 1;
    }
    // If no EOL found right after "stream", data_start_offset remains as is.
    // Some non-compliant PDFs might not have the EOL.

    // Ensure data_start_offset is within bounds before trying to slice from it.
    if data_start_offset >= obj_content_block.len() {
        return None; // No data possible after stream keyword and EOL.
    }

    // The actual stream data is from data_start_offset up to the beginning of "endstream".
    let stream_data_potential_block = obj_content_block.get(data_start_offset..)?;
    let rel_endstream_pos = memmem::find(stream_data_potential_block, ENDSTREAM_KW)?;
    let stream_data = stream_data_potential_block.get(..rel_endstream_pos)?;

    Some((dict_bytes, stream_data))
}

fn is_skippable(dict_bytes: &[u8]) -> bool {
    memmem::find(dict_bytes, b"/Type /Metadata").is_some()
        || memmem::find(dict_bytes, b"/Subtype /Image").is_some()
}

/// Finds and prepares information about potential text-containing streams in a PDF.
pub fn find_pdf_streams(pdf_bytes: &[u8]) -> Vec<FoundStreamInfo> {
    let mut found_streams = Vec::new();
    let mut i: usize = 0;
    let len = pdf_bytes.len();
    let mut prev_i = usize::MAX;

    while i < len {
        if i == prev_i && i != 0 {
            // Check if position 'i' got stuck
            eprintln!("Warning: Potential infinite loop detected at PDF offset {}. Aborting stream search.", i);
            break;
        }
        prev_i = i;

        // 1. Find the next " obj" keyword from the current offset 'i'
        if let Some(rel_obj_kw_pos) = memmem::find(&pdf_bytes[i..], OBJ_KW) {
            let abs_obj_kw_pos = i + rel_obj_kw_pos; // Absolute offset of " obj"

            // Default position to advance 'i' to if current object parsing fails.
            // This ensures we move at least past the " obj" keyword itself.
            let mut next_scan_target = abs_obj_kw_pos + OBJ_KW.len();

            // 2. Parse the object ID from bytes *before* " obj"
            if let Some(obj_id_str) = parse_object_id(&pdf_bytes[..abs_obj_kw_pos]) {
                // Determine where the object's actual content (dictionary/stream) starts.
                // This is after "X Y obj" and any immediate whitespace.
                let mut obj_content_start_offset = abs_obj_kw_pos + OBJ_KW.len();
                while obj_content_start_offset < len
                    && pdf_bytes[obj_content_start_offset].is_ascii_whitespace()
                {
                    obj_content_start_offset += 1;
                }

                if obj_content_start_offset < len {
                    // Ensure we are still within PDF bounds
                    // 3. Find the "endobj" keyword to define this object's content block
                    if let Some(rel_endobj_pos) =
                        memmem::find(&pdf_bytes[obj_content_start_offset..], ENDOBJ_KW)
                    {
                        let abs_endobj_pos = obj_content_start_offset + rel_endobj_pos;
                        let object_content_block =
                            &pdf_bytes[obj_content_start_offset..abs_endobj_pos];

                        // 4. Check if it's a stream and extract dictionary/stream data
                        if let Some((dict_bytes, raw_stream_data)) =
                            get_stream_and_dict(object_content_block)
                        {
                            if !is_skippable(dict_bytes) {
                                // 5. For now, only process FlateDecoded streams for simplicity
                                if memmem::find(dict_bytes, b"/FlateDecode").is_some() {
                                    match decompress_to_vec_zlib(raw_stream_data) {
                                        Ok(decompressed_data) => {
                                            found_streams.push(FoundStreamInfo {
                                                object_id: obj_id_str.clone(),
                                                dictionary_bytes: dict_bytes.to_vec(),
                                                decompressed_stream_data: decompressed_data,
                                            });
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Failed to decompress stream for object {}: {:?}",
                                                obj_id_str, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        // Successfully processed or identified this object, set next scan after "endobj"
                        next_scan_target = abs_endobj_pos + ENDOBJ_KW.len();
                    } else {
                        // No "endobj" found for this object. next_scan_target remains past " obj".
                        // eprintln!("Warning: Object {} at offset {} has no corresponding 'endobj'.", obj_id_str, obj_content_start_offset);
                    }
                }
            } else {
                eprintln!(
                    "Warning: Found 'obj' at offset {} but failed to parse its ID.",
                    abs_obj_kw_pos
                );
            }
            i = next_scan_target;
            continue;
        }

        i += 1;
    }
    found_streams
}

#[cfg(test)]
mod tests {

    use super::*;

    static SAMPLE_PDF: &[u8] = include_bytes!("../../sample-pdfs/digitally_signed.pdf");
    static BANK_CERT_PDF: &[u8] = include_bytes!("../../samples-private/bank-cert.pdf");

    // Dummy zlib compressed data for "test"
    const COMPRESSED_TEXT_BYTES: [u8; 12] = [120, 156, 43, 73, 45, 46, 1, 0, 4, 93, 1, 193]; // "test"

    #[test]
    fn test_parse_object_id_logic() {
        assert_eq!(parse_object_id(b"1 0"), Some("1_0".to_string()));
        assert_eq!(parse_object_id(b"  12  0  "), Some("12_0".to_string()));
        assert_eq!(parse_object_id(b"123 456"), Some("123_456".to_string()));
        assert_eq!(parse_object_id(b"1 0 "), Some("1_0".to_string()));
        assert_eq!(parse_object_id(b"0 1"), Some("0_1".to_string())); // Object ID 0
        assert_eq!(parse_object_id(b" 42 1 "), Some("42_1".to_string())); // Leading space on object num
    }

    #[test]
    fn test_parse_object_id_failures() {
        assert_eq!(parse_object_id(b"1 "), None); // Missing generation
        assert_eq!(parse_object_id(b" 0"), None); // Missing object number
        assert_eq!(parse_object_id(b"abc 0"), None); // Non-digit object number
        assert_eq!(parse_object_id(b"1 abc"), None); // Non-digit generation
        assert_eq!(parse_object_id(b""), None); // Empty
        assert_eq!(parse_object_id(b" "), None); // Just space
        assert_eq!(parse_object_id(b"obj"), None); // Just keyword
        assert_eq!(parse_object_id(b"10"), None); // Missing generation
        assert_eq!(parse_object_id(b"  1  "), None); // Missing generation
    }

    #[test]
    fn test_get_stream_and_dict_eol_variants() {
        let content_crlf = b"<< /L 5 >>stream\r\nHello\r\nendstream"; // Standard EOL after stream
        let (dict1, stream1) = get_stream_and_dict(content_crlf).unwrap();
        assert_eq!(String::from_utf8_lossy(dict1).trim(), "<< /L 5 >>");
        assert_eq!(stream1, b"Hello\r\n"); // Stream content includes its own EOLs

        let content_lf = b"<< /L 5 >>stream\nHello\nendstream"; // LF EOL after stream
        let (dict2, stream2) = get_stream_and_dict(content_lf).unwrap();
        assert_eq!(String::from_utf8_lossy(dict2).trim(), "<< /L 5 >>");
        assert_eq!(stream2, b"Hello\n");

        let content_no_eol = b"<< /L 5 >>streamHelloendstream"; // Non-compliant: no EOL after stream
        let (dict3, stream3) = get_stream_and_dict(content_no_eol).unwrap();
        assert_eq!(String::from_utf8_lossy(dict3).trim(), "<< /L 5 >>");
        assert_eq!(stream3, b"Hello");

        let content_only_endstream = b"streamendstream"; // Minimal case
        let (dict4, stream4) = get_stream_and_dict(content_only_endstream).unwrap();
        assert!(dict4.is_empty());
        assert!(stream4.is_empty());

        let content_no_endstream_kw = b"<< /L 5 >>streamHello";
        assert!(get_stream_and_dict(content_no_endstream_kw).is_none());
    }

    #[test]
    fn test_find_streams_with_test_bytes() {
        let mut pdf_data = Vec::new();
        pdf_data.extend_from_slice(b"1 0 obj << /Filter /FlateDecode /Length 12 >> stream\r\n");
        pdf_data.extend_from_slice(&COMPRESSED_TEXT_BYTES); // "test" compressed
        pdf_data.extend_from_slice(b"\r\nendstream endobj\n");
        // Skippable object
        pdf_data.extend_from_slice(
            b"2 0 obj\n<< /Type /Metadata >>\nstream\nblah\nendstream\nendobj\n",
        );
        // Non-FlateDecoded stream object
        pdf_data.extend_from_slice(b"3 0 obj << /Length 4 /Filter /ASCIIHexDecode >> stream\n48656c6c6f\nendstream endobj\n"); // "Hello" hex encoded
                                                                                                                               // Object without a stream
        pdf_data.extend_from_slice(b"4 0 obj << /Type /Page >> endobj\n");

        let streams = find_pdf_streams(&pdf_data);
        assert_eq!(
            streams.len(),
            1,
            "Should find only one FlateDecoded, non-skippable stream."
        );

        let stream_info = &streams[0];
        assert_eq!(stream_info.object_id, "1_0");
        assert!(String::from_utf8_lossy(&stream_info.dictionary_bytes).contains("/FlateDecode"));
        assert_eq!(
            String::from_utf8_lossy(&stream_info.decompressed_stream_data),
            "test"
        );
    }

    #[test]
    fn test_malformed_pdf_no_endobj_handling() {
        // Object starts but "endobj" is missing. Loop should not be infinite.
        let pdf_data = b"1 0 obj << /Key /Val >> stream\nSome stream data here\nendstream\n% Missing endobj here";
        let streams = find_pdf_streams(pdf_data);
        // No streams should be successfully processed and added because endobj is missing.
        assert_eq!(
            streams.len(),
            0,
            "No streams should be found if object is malformed (missing endobj)."
        );
    }

    #[test]
    fn test_empty_pdf_input() {
        let pdf_data = b"";
        let streams = find_pdf_streams(pdf_data);
        assert!(
            streams.is_empty(),
            "No streams should be found in an empty PDF."
        );
    }

    #[test]
    fn test_pdf_with_no_obj_keywords() {
        let pdf_data =
            b"%PDF-1.4\n%This PDF has no objects defined with 'obj'.\ntrailer << /Size 1 >>";
        let streams = find_pdf_streams(pdf_data);

        assert!(
            streams.is_empty(),
            "No streams should be found if no 'obj' keywords are present."
        );
    }

    #[test]
    fn test_actual_pdf_digitally_signed() {
        let streams = find_pdf_streams(SAMPLE_PDF);

        println!("Found {} streams in digitally_signed.pdf", streams.len());

        assert!(
            !streams.is_empty(),
            "Expected to find some streams in digitally_signed.pdf"
        );
    }

    #[test]
    fn test_actual_pdf_bank_cert() {
        let streams = find_pdf_streams(BANK_CERT_PDF);

        println!("Found {} streams in bank-cert.pdf", streams.len());
        assert!(
            !streams.is_empty(),
            "Expected to find some streams in bank-cert.pdf"
        );
    }
}
