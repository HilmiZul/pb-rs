//! Identifier and secret generation, matching `tools/security/random.go`.

use rand::Rng;

/// `core.DefaultIdAlphabet`
pub const ID_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
/// `core.DefaultIdLength`
pub const ID_LENGTH: usize = 15;
/// `security.defaultRandomAlphabet`
pub const RANDOM_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Equivalent of `core.GenerateDefaultRandomId`.
pub fn default_random_id() -> String {
    pseudorandom_string(ID_LENGTH, ID_ALPHABET)
}

/// Equivalent of `security.RandomString` (cryptographically random).
pub fn random_string(length: usize) -> String {
    random_string_with_alphabet(length, RANDOM_ALPHABET)
}

/// Equivalent of `security.RandomStringWithAlphabet`.
pub fn random_string_with_alphabet(length: usize, alphabet: &str) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Equivalent of `security.PseudorandomStringWithAlphabet`.
fn pseudorandom_string(length: usize, alphabet: &str) -> String {
    let chars: Vec<char> = alphabet.chars().collect();
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_15_lowercase_alnum() {
        for _ in 0..100 {
            let id = default_random_id();
            assert_eq!(id.len(), 15);
            assert!(id.chars().all(|c| ID_ALPHABET.contains(c)));
        }
    }

    #[test]
    fn secrets_are_43_alnum() {
        let s = random_string(43);
        assert_eq!(s.len(), 43);
        assert!(s.chars().all(|c| RANDOM_ALPHABET.contains(c)));
    }
}
