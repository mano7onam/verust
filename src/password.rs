pub struct PasswordValidator {
    special_chars_required: bool,
    deny_sequential_chars: bool,
    deny_sequential_numbers: bool,
    deny_common_passwords: bool,
}

impl PasswordValidator {
    pub fn new(special_chars_required: bool, deny_sequential_chars: bool,
               deny_sequential_numbers: bool, deny_common_passwords: bool) -> PasswordValidator {
        PasswordValidator {
            special_chars_required,
            deny_sequential_chars,
            deny_sequential_numbers,
            deny_common_passwords,
        }
    }

    pub fn validate(&self, pass: &str) -> bool {
        let length = pass.len();
        let digits = pass.chars().filter(|c| c.is_digit(10)).count();
        let uppercase = pass.chars().filter(|c| c.is_uppercase()).count();
        let lowercase = pass.chars().filter(|c| c.is_lowercase()).count();
        let special_chars = pass.chars().filter(|c| !c.is_alphanumeric()).count();
        let simplified_pass = pass.chars().collect::<Vec<char>>().windows(2).any(|w| w[0] == w[1]);

        let length_valid = length >= 8 && length <= 64;
        let digits_valid = digits > 0;
        let uppercase_valid = uppercase > 0;
        let lowercase_valid = lowercase > 0;
        let special_chars_valid = !self.special_chars_required || special_chars > 0;
        let simplified_pass_valid = !self.deny_sequential_chars || !simplified_pass;

        let sequential_numbers = pass.chars()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|w| w[0].is_numeric() && w[0] == (w[1] as u8 - 1) as char);

        let common_passwords = ["123456", "qwerty", "password"];
        let is_common_password = common_passwords.contains(&pass);

        let repeating_substrings = {
            let mut repetition = false;
            for window in 2..=pass.len() / 2 {
                if repetition {
                    break;
                }
                for chunk in pass.as_bytes().windows(window) {
                    let pattern = String::from_utf8(chunk.to_vec()).unwrap();
                    let remaining = &pass[chunk.len()..];
                    if remaining.contains(&pattern) {
                        repetition = true;
                        break;
                    }
                }
            };
            repetition
        };

        let sequential_numbers_valid = !self.deny_sequential_numbers || !sequential_numbers;
        let common_passwords_valid = !self.deny_common_passwords || !is_common_password;
        let repeating_substrings_valid = !repeating_substrings;

        length_valid && digits_valid && uppercase_valid && lowercase_valid && special_chars_valid && simplified_pass_valid &&
        sequential_numbers_valid && common_passwords_valid && repeating_substrings_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password() {
        let password_validator = PasswordValidator::new(true, true, true, true);

        // Basic Tests
        // assert!(!password_validator.validate("Password123"));
        // assert!(password_validator.validate("Passw0rd!!!"));
        assert!(password_validator.validate("Pasword132!")); // Lacks special chars and uppercase

        // Length Checks
        assert!(!password_validator.validate("Sh0rt!")); // Too short
        assert!(!password_validator.validate(&"a".repeat(65))); // Too long

        // Content Checks
        assert!(!password_validator.validate("password")); // Lacks digits and uppercase
        assert!(!password_validator.validate("12345678")); // Lacks letters
        assert!(!password_validator.validate("PASSWORD123")); // Lacks lowercase
        assert!(!password_validator.validate("password123")); // Lacks special chars and uppercase
        assert!(password_validator.validate("Pasword132!")); // Lacks special chars and uppercase

        // Boundary Checks
        assert!(!password_validator.validate("password123!")); // Lacks uppercase
        assert!(!password_validator.validate("P@ssw0rd")); // Contains ss
        assert!(password_validator.validate("P@sw0rd")); // All is ok

        // Special condition checks
        assert!(!password_validator.validate("Password1234567")); // Sequence of digits
        assert!(!password_validator.validate("password")); // Common password
        assert!(!password_validator.validate("ababab")); // Repeated substrings

        // Edge cases
        assert!(!password_validator.validate("Ab1!Ab1!")); // Repeated substrings
        assert!(!password_validator.validate("A1234567890b!")); // Sequential numbers
        //assert!(password_validator.validate("P1@ssword")); // All conditions met
    }
}