pub fn validate(pass: &str) -> bool {
    let length = pass.len();
    let digits = pass.chars().filter(|c| c.is_digit(10)).count();
    let letters = pass.chars().filter(|c| c.is_alphabetic()).count();

    length >= 8 && length <= 64 && digits > 0 && letters > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password() {
        assert!(validate("password123"));
        assert!(validate("password!!!123"));
        assert!(!validate("pass123"));  // Too short
        assert!(!validate("password"));  // Lacks digits
        assert!(!validate("12345678"));  // Lacks letters
    }
}