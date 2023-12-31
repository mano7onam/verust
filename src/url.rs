extern crate regex;
use regex::Regex;

pub fn validate(url: &str) -> bool {
    let url_regex = Regex::new(r"^((http|https):\/\/)?([a-zA-Z0-9]+\.[a-zA-Z0-9]+)+[\w\-\._~:\/\?#[\]@!\$&'\(\)\*\+,;=.]+$").unwrap();
    url_regex.is_match(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url() {
        assert!(validate("http://example.com"));
        assert!(validate("https://example.com"));
        assert!(validate("https://www.example.com"));
        assert!(validate("https://www.example.com/path/to/resource"));
        assert!(validate("https://example.com/path/to/resource?with=query&params"));
        assert!(validate("www.example.com"));
        assert!(!validate("example"));
        assert!(!validate("://example.com"));
    }
}