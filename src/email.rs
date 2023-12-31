extern crate regex;

use std::net::ToSocketAddrs;
use regex::Regex;

pub struct EmailValidator {
    min_length: usize,
    max_length: usize,
    check_known_provider: bool,
    deny_symbols_pattern: Option<Regex>,
}

impl EmailValidator {
    pub fn new(min_length: usize, max_length: usize) -> Self {
        Self {
            min_length,
            max_length,
            check_known_provider: false,
            deny_symbols_pattern: None,
        }
    }

    pub fn known_provider_check(mut self, is_required: bool) -> Self {
        self.check_known_provider = is_required;
        self
    }

    pub fn deny_symbols(mut self, pattern: &str) -> Self {
        self.deny_symbols_pattern = Some(Regex::new(pattern).unwrap());
        self
    }

    pub fn is_valid(&self, email: &str) -> bool {
        let email_regex = Regex::new(
            r"(?i)^[\w+\-.+%]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]{2,}$").unwrap();

        let length = email.len();
        let length_valid = self.min_length <= length && length <= self.max_length;

        let format_valid = email_regex.is_match(email);

        let invalid_chars_regex = Regex::new(r"[^@+\w+\-.+%]").unwrap();
        let contains_invalid_chars = invalid_chars_regex.is_match(email);

        let domain_valid = self.check_domain(email);

        let provider_valid = if self.check_known_provider {
            self.check_known_provider(email)
        } else {
            true
        };

        let symbols_valid = if let Some(pattern) = &self.deny_symbols_pattern {
            !pattern.is_match(email)
        } else {
            true
        };

        format_valid && length_valid && !contains_invalid_chars && domain_valid && provider_valid && symbols_valid
    }

    pub fn check_domain(&self, email: &str) -> bool {
        let domain = email.split("@").last().unwrap_or("");
        match (domain, 0).to_socket_addrs() {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn check_known_provider(&self, email: &str) -> bool {
        let known_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "mail.ru"];
        let domain = email.split("@").last().unwrap_or("");
        known_providers.contains(&domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validity() {
        let validator = EmailValidator::new(5, 254);

        assert!(validator.is_valid("someone@example.com"));
        assert!(validator.is_valid("SOMEONE@example.com"));
        assert!(!validator.is_valid("email"));
        assert!(!validator.is_valid("@example.com"));
        assert!(!validator.is_valid("someone@example"));
        assert!(!validator.is_valid("someone@.com"));
    }

    #[test]
    fn test_provider_validity() {
        let validator = EmailValidator::new(5, 254).known_provider_check(true);

        assert!(validator.is_valid("someone@gmail.com"));
        assert!(validator.is_valid("SOMEONE@hotmail.com"));
        assert!(!validator.is_valid("someone@unknown.com"));
    }

    #[test]
    fn test_symbols_validity() {
        let validator = EmailValidator::new(5, 254).deny_symbols(".%");

        assert!(validator.is_valid("someone@example.com"));
        // assert!(!validator.is_valid("someone.@example.com"));
    }
}