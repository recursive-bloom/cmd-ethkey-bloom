use super::Brain;
use parity_crypto::publickey::{Generator, KeyPair, Error};
use parity_wordlist as wordlist;

/// Tries to find brain-seed keypair with address starting with given prefix.
pub struct BrainPrefix {
    prefix: Vec<u8>,
    iterations: usize,
    no_of_words: usize,
    last_phrase: String,
}

impl BrainPrefix {
    pub fn new(prefix: Vec<u8>, iterations: usize, no_of_words: usize) -> Self {
        BrainPrefix {
            prefix,
            iterations,
            no_of_words,
            last_phrase: String::new(),
        }
    }

    pub fn phrase(&self) -> &str {
        &self.last_phrase
    }

    pub fn generate(&mut self) -> Result<KeyPair, Error> {
        for _ in 0..self.iterations {
            let phrase = wordlist::random_phrase(self.no_of_words);
            let keypair = Brain::new(phrase.clone()).generate();
            if keypair.address().as_ref().starts_with(&self.prefix) {
                self.last_phrase = phrase;
                return Ok(keypair)
            }
        }

        Err(Error::Custom("Could not find keypair".into()))
    }
}
