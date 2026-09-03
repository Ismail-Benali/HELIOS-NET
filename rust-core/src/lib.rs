// HELIOS-NET :: rust-core/src/lib.rs
// نواة مرجعية — مثال صغير قائم كي يثبت تجهيز البنية متى توفر cargo.

/// يُعيد تقدير عائلة من TTL — نسخة Rust من C fingerprint، للمقارنة.
pub fn ttl_family(ttl: i32) -> &'static str {
    match ttl {
        56..=64 => "Linux/Unix (TTL~64)",
        120..=128 => "Windows (TTL~128)",
        240..=255 => "Router/Network (TTL~255)",
        _ => "Unknown",
    }
}

// نقطة حديثة للتوازي لاحقًا: إيقاع مشعب عبر مجموعات مؤشرات.
pub fn scheduled_dwells(steps: usize, base: f64, jitter: f64) -> Vec<f64> {
    (0..steps).map(|_| base).collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_linux() {
        assert_eq!(ttl_family(64), "Linux/Unix (TTL~64)");
    }

    #[test]
    fn dwell_default() {
        assert_eq!(scheduled_dwells(3, 0.2, 0.1), vec![0.2, 0.2, 0.2]);
    }
}
