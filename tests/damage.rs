//! Any input gives events, problems or nothing, never a panic.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\n\"{}\\[\\],:]{0,600}") {
        let _ = cloudlogs::read(text.as_bytes());
        let _ = cloudlogs::detect(text.as_bytes());
    }

    #[test]
    fn records_cut_anywhere(cut in 0usize..700) {
        let samples: [&[u8]; 2] = [
            include_bytes!("fixtures/written/cloudtrail-s3.json"),
            include_bytes!("fixtures/written/m365-purview.csv"),
        ];
        for sample in samples {
            let _ = cloudlogs::read(&sample[..cut.min(sample.len())]);
            let _ = cloudlogs::detect(&sample[..cut.min(sample.len())]);
        }
    }

    #[test]
    fn deep_nesting(depth in 0usize..400) {
        let text = format!("{{\"logName\":\"x\",\"timestamp\":\"2024-01-01T00:00:00Z\",\"a\":{}{}}}", "[".repeat(depth), "]".repeat(depth));
        let _ = cloudlogs::read(text.as_bytes());
    }
}
