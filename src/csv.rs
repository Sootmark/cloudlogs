//! CSV as RFC 4180 writes it: commas, quoted fields with doubled quotes,
//! line breaks inside quotes.

/// The rows of `text`, each with the line it starts on (from 1).
pub(crate) fn rows(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut line = 1;
    let mut start = 1;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if field.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut field)),
            ('\r', false) => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut field));
                if row.iter().any(|f| !f.is_empty()) {
                    rows.push((start, std::mem::take(&mut row)));
                }
                row.clear();
                line += 1;
                start = line;
            }
            ('\n', true) => {
                field.push('\n');
                line += 1;
            }
            (c, _) => field.push(c),
        }
    }
    row.push(field);
    if row.iter().any(|f| !f.is_empty()) {
        rows.push((start, row));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_and_line_breaks() {
        let rows = rows("a,b\r\n\"x,\"\"y\"\"\",\"1\n2\"\n\n3,4");
        assert_eq!(
            rows,
            [
                (1, vec!["a".to_owned(), "b".to_owned()]),
                (2, vec!["x,\"y\"".to_owned(), "1\n2".to_owned()]),
                (5, vec!["3".to_owned(), "4".to_owned()]),
            ]
        );
    }
}
