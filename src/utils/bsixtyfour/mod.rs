use base64::Engine;

pub fn b64_vec_encode(input: &[u8]) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .encode(input)
        .into_bytes()
}
