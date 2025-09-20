use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::blocking::Client;
use rodio::Sink;
use std::{error::Error, io::Cursor};

/// Panggil TTS lalu putar hasilnya.
/// Param cukup teks bebas; voice default "id-ID-ArdiNeural".
pub fn speak(text: &str) -> Result<(), Box<dyn Error>> {
    // 1) Panggil API TTS
    let client = Client::new();
    let resp = client
        .post("https://edgetts-fastapi.vercel.app/text-to-speech/")
        .json(&serde_json::json!({
            "text": text,
            "voice": "id-ID-ArdiNeural",
            "subtitle": false,
            "words_per_subtitle": 8
        }))
        .send()?
        .error_for_status()? // biar cepat ketahuan kalau non-2xx
        .json::<serde_json::Value>()?;

    // 2) Ambil audio base64
    let mut b64 = resp["audio"]
        .as_str()
        .ok_or("Field 'audio' tidak ada / bukan string")?
        .to_string();

    // (Opsional) kalau API suatu saat mengirim "data:audio/mp3;base64,...."
    if let Some(idx) = b64.find(",") {
        if b64[..idx].contains("base64") {
            b64 = b64[idx + 1..].to_string();
        }
    }

    let audio_bytes = STANDARD.decode(b64.as_bytes())?;

    // 3) Siapkan output rodio 0.21 (tanpa try_default)
    let stream = rodio::OutputStreamBuilder::open_default_stream()?;
    let mixer = stream.mixer();

    // 4) Play dari memory; rodio 0.21 akan mem-probe format (mp3/wav/ogg) otomatis
    let cursor = Cursor::new(audio_bytes);
    let sink: Sink = rodio::play(mixer, cursor)?;
    // sink.set_volume(0.9); // kalau mau atur volume

    // 5) Tunggu sampai selesai
    sink.sleep_until_end();
    Ok(())
}
