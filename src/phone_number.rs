
extern crate regex;
use regex::Regex;

pub fn validate(phone: &str) -> bool {
    let phone_regex = Regex::new(r"^\+?[1-9]\d{1,14}$").unwrap();
    phone_regex.is_match(phone)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_phone_number() {
        assert!(validate("+1234567890"));  // International format
        assert!(validate("1234567890"));  // Local format (assuming the country has 10 digits format)
        assert!(!validate("1234"));  // Too short
        assert!(!validate("1234567890123456"));  // Too long
        assert!(!validate("+1234abcd"));  // Invalid characters
    }
}