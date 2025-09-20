use crate::error::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use regex::Regex;

pub fn generate_firebase_fid() -> Result<String> {
    let mut fid = [0u8; 17];
    OsRng.fill_bytes(&mut fid);
    fid[0] = 0b0111_0000 | (fid[0] & 0b0000_1111);
    Ok(BASE64_STANDARD.encode(fid))
}

pub fn contains<T: PartialEq>(items: &[T], target: &T) -> bool {
    items.iter().any(|item| item == target)
}

pub fn remove_first(items: &mut Vec<String>, target: &str) {
    if let Some(pos) = items.iter().position(|item| item == target) {
        items.remove(pos);
    }
}

pub fn parse_rupiah_nominal(text: &str) -> i64 {
    // Cek apakah teks mengandung "qris-transaction" atau "transaction-in" (case-insensitive)
    if !text.to_lowercase().contains("qris-transaction")
        && !text.to_lowercase().contains("transaction-in")
    {
        return 0;
    }

    // Regex untuk mencari pola "Rp" + optional space + angka (dengan atau tanpa titik ribuan)
    let re = Regex::new(r"(?i)rp\s*([\d\.]+)").expect("Invalid regex");

    for cap in re.captures_iter(text) {
        if let Some(matched) = cap.get(1) {
            let cleaned = matched.as_str().replace(".", "");
            if let Ok(nominal) = cleaned.parse::<i64>() {
                return nominal;
            }
        }
    }

    0 // fallback jika tidak ditemukan nominal meskipun syarat keyword terpenuhi
}
pub fn terbilang(n: i64) -> String {
    if n == 0 {
        return "nol".to_string();
    }

    let mut result = String::new();
    let neg = if n < 0 { "minus " } else { "" };
    let n = n.abs();

    // Satuan
    let satuan = [
        "", "satu", "dua", "tiga", "empat", "lima", "enam", "tujuh", "delapan", "sembilan",
    ];

    // Belasan
    let belasan = [
        "sepuluh",
        "sebelas",
        "dua belas",
        "tiga belas",
        "empat belas",
        "lima belas",
        "enam belas",
        "tujuh belas",
        "delapan belas",
        "sembilan belas",
    ];

    // Puluhan
    let puluhan = [
        "",
        "sepuluh",
        "dua puluh",
        "tiga puluh",
        "empat puluh",
        "lima puluh",
        "enam puluh",
        "tujuh puluh",
        "delapan puluh",
        "sembilan puluh",
    ];

    fn process_chunk(
        num: i64,
        satuan: &[&str; 10],
        belasan: &[&str; 10],
        puluhan: &[&str; 10],
    ) -> String {
        let mut s = String::new();
        let ratusan = num / 100;
        let sisa = num % 100;

        if ratusan > 0 {
            if ratusan == 1 {
                s.push_str("seratus");
            } else {
                s.push_str(satuan[ratusan as usize]);
                s.push_str(" ratus");
            }
            if sisa > 0 {
                s.push_str(" ");
            }
        }

        if sisa > 0 {
            if sisa < 10 {
                s.push_str(satuan[sisa as usize]);
            } else if sisa < 20 {
                s.push_str(belasan[(sisa - 10) as usize]);
            } else {
                let puluh = sisa / 10;
                let sat = sisa % 10;
                s.push_str(puluhan[puluh as usize]);
                if sat > 0 {
                    s.push_str(" ");
                    s.push_str(satuan[sat as usize]);
                }
            }
        }

        s
    }

    let miliar = n / 1_000_000_000;
    let sisa_miliar = n % 1_000_000_000;

    let juta = sisa_miliar / 1_000_000;
    let sisa_juta = sisa_miliar % 1_000_000;

    let ribu = sisa_juta / 1_000;
    let sisa_ribu = sisa_juta % 1_000;

    let mut parts = Vec::new();

    if miliar > 0 {
        let chunk = process_chunk(miliar, &satuan, &belasan, &puluhan);
        parts.push(if chunk.is_empty() || chunk == "satu" {
            "satu miliar".to_string()
        } else {
            format!("{} miliar", chunk)
        });
    }

    if juta > 0 {
        let chunk = process_chunk(juta, &satuan, &belasan, &puluhan);
        parts.push(if chunk.is_empty() || chunk == "satu" {
            "satu juta".to_string()
        } else {
            format!("{} juta", chunk)
        });
    }

    if ribu > 0 {
        let chunk = process_chunk(ribu, &satuan, &belasan, &puluhan);
        parts.push(if chunk.is_empty() {
            "seribu".to_string()
        } else if chunk == "satu" {
            "seribu".to_string()
        } else {
            format!("{} ribu", chunk)
        });
    }

    if sisa_ribu > 0 {
        let chunk = process_chunk(sisa_ribu, &satuan, &belasan, &puluhan);
        parts.push(chunk);
    }

    result.push_str(neg);
    result.push_str(&parts.join(" "));

    result
}
