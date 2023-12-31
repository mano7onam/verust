extern crate regex;
use regex::Regex;

pub fn validate(email: &str) -> bool {
    let email_regex = Regex::new(r"(?i)^[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+$").unwrap();
    email_regex.is_match(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email() {
        assert!(validate("someone@example.com"));
        assert!(validate("SOMEONE@example.com"));
        assert!(!validate("email"));
        assert!(!validate("@example.com"));
        assert!(!validate("someone@example"));
        assert!(!validate("someone@.com"));
    }
}