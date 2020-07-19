use parity_crypto::publickey::{Random, Generator, KeyPair, Error};

/// Tries to find keypair with address starting with given prefix.
pub struct Prefix {
    prefix: Vec<u8>,
    iterations: usize,
}

impl Prefix {
    pub fn new(prefix: Vec<u8>, iterations: usize) -> Self {
        Prefix { prefix, iterations }
    }

    pub fn generate(&mut self) -> Result<KeyPair, Error> {
        for _ in 0..self.iterations {
            let keypair = Random.generate();
            if keypair.address().as_ref().starts_with(&self.prefix) {
                return Ok(keypair)
            }
        }
        Err(Error::Custom("Could not find keypair".into()))
    }
}
