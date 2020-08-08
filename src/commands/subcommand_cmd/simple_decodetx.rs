use std::ops::Deref;
use keccak_hash::keccak;
use ethereum_types::{H256, H160, Address, U256, BigEndianHash};
use parity_crypto::publickey::{Signature, Secret, Public, recover, public_to_address};
use rlp::{self, RlpStream, Rlp, DecoderError, Encodable};
use std::str::FromStr;  //for[ Address::from_str(); ]
use rustc_hex::FromHex;
use rustc_hex::ToHex;
use super::error;
type Bytes = Vec<u8>;

/// Fake address for unsigned transactions as defined by EIP-86.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// System sender address for internal state updates.
pub const SYSTEM_ADDRESS: Address = H160([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xff,0xff, 0xff, 0xff, 0xfe]);


/// Transaction action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Create creates new contract.
    Create,
    /// Calls contract at given address.
    /// In the case of a transfer, this is the receiver's address.'
    Call(Address),
}

impl Default for Action {
    fn default() -> Action { Action::Create }
}

impl rlp::Decodable for Action {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.is_empty() {
            if rlp.is_data() {
                Ok(Action::Create)
            } else {
                Err(DecoderError::RlpExpectedToBeData)
            }
        } else {
            Ok(Action::Call(rlp.as_val()?))
        }
    }
}

impl rlp::Encodable for Action {
    fn rlp_append(&self, s: &mut RlpStream) {
        match *self {
            Action::Create => s.append_internal(&""),
            Action::Call(ref addr) => s.append_internal(addr),
        };
    }
}


/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Nonce.
    pub nonce: U256,
    /// Gas price.
    pub gas_price: U256,
    /// Gas paid up front for transaction execution.
    pub gas: U256,
    /// Action, can be either call or contract create.
    pub action: Action,
    /// Transfered value.
    pub value: U256,
    /// Transaction data.
    pub data: Bytes,
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTransaction {
    /// Plain Transaction.
    unsigned: Transaction,
    /// The V field of the signature; the LS bit described which half of the curve our point falls
    /// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
    v: u64,
    /// The R field of the signature; helps describe the point on the curve.
    r: U256,
    /// The S field of the signature; helps describe the point on the curve.
    s: U256,
    /// Hash of the transaction
    hash: H256,
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignedTransaction {
    transaction: UnverifiedTransaction,
    sender: Address,
    public: Option<Public>,
}

impl Transaction {
    /// Append object with a without signature into RLP stream
    pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream, chain_id: Option<u64>) {
        s.begin_list(if chain_id.is_none() { 6 } else { 9 });
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        if let Some(n) = chain_id {
            s.append(&n);
            s.append(&0u8);
            s.append(&0u8);
        }
    }
}


impl Transaction {
    /// The message hash of the transaction.
    pub fn hash(&self, chain_id: Option<u64>) -> H256 {
        let mut stream = RlpStream::new();
        self.rlp_append_unsigned_transaction(&mut stream, chain_id);
        keccak(stream.as_raw())
    }

    /// Signs the transaction as coming from `sender`.
    pub fn sign(self, secret: &Secret, chain_id: Option<u64>) -> SignedTransaction {
        let sig = parity_crypto::publickey::sign(secret, &self.hash(chain_id))
            .expect("data is valid and context has signing capabilities; qed");
        SignedTransaction::new(self.with_signature(sig, chain_id))
            .expect("secret is valid so it's recoverable")
    }

    /// Signs the transaction with signature.
    pub fn with_signature(self, sig: Signature, chain_id: Option<u64>) -> UnverifiedTransaction {
        UnverifiedTransaction {
            unsigned: self,
            r: sig.r().into(),
            s: sig.s().into(),
            v: signature::add_chain_replay_protection(sig.v() as u64, chain_id),
            hash: H256::zero(),
        }.compute_hash()
    }

    /// Useful for test incorrectly signed transactions.
    #[cfg(test)]
    pub fn invalid_sign(self) -> UnverifiedTransaction {
        UnverifiedTransaction {
            unsigned: self,
            r: U256::one(),
            s: U256::one(),
            v: 0,
            hash: H256::zero(),
        }.compute_hash()
    }

    /// Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
    pub fn fake_sign(self, from: Address) -> SignedTransaction {
        SignedTransaction {
            transaction: UnverifiedTransaction {
                unsigned: self,
                r: U256::one(),
                s: U256::one(),
                v: 0,
                hash: H256::zero(),
            }.compute_hash(),
            sender: from,
            public: None,
        }
    }

    /// Legacy EIP-86 compatible empty signature.
    /// This method is used in json tests as well as
    /// signature verification tests.
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn null_sign(self, chain_id: u64) -> SignedTransaction {
        SignedTransaction {
            transaction: UnverifiedTransaction {
                unsigned: self,
                r: U256::zero(),
                s: U256::zero(),
                v: chain_id,
                hash: H256::zero(),
            }.compute_hash(),
            sender: UNSIGNED_SENDER,
            public: None,
        }
    }
}


impl rlp::Encodable for SignedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) { self.transaction.rlp_append_sealed_transaction(s) }
}

impl Deref for SignedTransaction {
    type Target = UnverifiedTransaction;
    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl SignedTransaction {
    /// Try to verify transaction and recover sender.
    pub fn new(transaction: UnverifiedTransaction) -> Result<Self, parity_crypto::publickey::Error> {
        if transaction.is_unsigned() {
            return Err(parity_crypto::publickey::Error::InvalidSignature);
        }
        let public = transaction.recover_public()?;
        let sender = public_to_address(&public);
        Ok(SignedTransaction {
            transaction,
            sender,
            public: Some(public),
        })
    }

    /// Returns transaction sender.
    pub fn sender(&self) -> Address {
        self.sender
    }

    /// Returns a public key of the sender.
    pub fn public_key(&self) -> Option<Public> {
        self.public
    }

    /// Checks is signature is empty.
    pub fn is_unsigned(&self) -> bool {
        self.transaction.is_unsigned()
    }

    /// Deconstructs this transaction back into `UnverifiedTransaction`
    pub fn deconstruct(self) -> (UnverifiedTransaction, Address, Option<Public>) {
        (self.transaction, self.sender, self.public)
    }
}


impl Deref for UnverifiedTransaction {
    type Target = Transaction;

    fn deref(&self) -> &Self::Target {
        &self.unsigned
    }
}

impl rlp::Decodable for UnverifiedTransaction {
    fn decode(d: &Rlp) -> Result<Self, DecoderError> {
        if d.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let hash = keccak(d.as_raw());
        Ok(UnverifiedTransaction {
            unsigned: Transaction {
                nonce: d.val_at(0)?,
                gas_price: d.val_at(1)?,
                gas: d.val_at(2)?,
                action: d.val_at(3)?,
                value: d.val_at(4)?,
                data: d.val_at(5)?,
            },
            v: d.val_at(6)?,
            r: d.val_at(7)?,
            s: d.val_at(8)?,
            hash,
        })
    }
}

impl rlp::Encodable for UnverifiedTransaction {
    fn rlp_append(&self, s: &mut RlpStream) { self.rlp_append_sealed_transaction(s) }
}


impl UnverifiedTransaction {
    /// Used to compute hash of created transactions
    fn compute_hash(mut self) -> UnverifiedTransaction {
        let hash = keccak(&*self.rlp_bytes());
        self.hash = hash;
        self
    }

    /// Checks if the signature is empty.
    pub fn is_unsigned(&self) -> bool {
        self.r.is_zero() && self.s.is_zero()
    }

    /// Returns transaction receiver, if any
    pub fn receiver(&self) -> Option<Address> {
        match self.unsigned.action {
            Action::Create => None,
            Action::Call(receiver) => Some(receiver),
        }
    }

    /// Append object with a signature into RLP stream
    fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.data);
        s.append(&self.v);
        s.append(&self.r);
        s.append(&self.s);
    }

    ///	Reference to unsigned part of this transaction.
    pub fn as_unsigned(&self) -> &Transaction {
        &self.unsigned
    }

    /// Returns standardized `v` value (0, 1 or 4 (invalid))
    pub fn standard_v(&self) -> u8 { signature::check_replay_protection(self.v) }

    /// The `v` value that appears in the RLP.
    pub fn original_v(&self) -> u64 { self.v }

    /// The chain ID, or `None` if this is a global transaction.
    pub fn chain_id(&self) -> Option<u64> {
        match self.v {
            v if self.is_unsigned() => Some(v),
            v if v >= 35 => Some((v - 35) / 2),
            _ => None,
        }
    }

    /// Construct a signature object from the sig.
    pub fn signature(&self) -> Signature {
        let r: H256 = BigEndianHash::from_uint(&self.r);
        let s: H256 = BigEndianHash::from_uint(&self.s);
        Signature::from_rsv(&r, &s, self.standard_v())
    }

    /// Checks whether the signature has a low 's' value.
    pub fn check_low_s(&self) -> Result<(), parity_crypto::publickey::Error> {
        if !self.signature().is_low_s() {
            Err(parity_crypto::publickey::Error::InvalidSignature)
        } else {
            Ok(())
        }
    }

    /// Get the hash of this transaction (keccak of the RLP).
    pub fn hash(&self) -> H256 {
        self.hash
    }

    /// Recovers the public key of the sender.
    pub fn recover_public(&self) -> Result<Public, parity_crypto::publickey::Error> {
        Ok(recover(&self.signature(), &self.unsigned.hash(self.chain_id()))?)
    }

    /// Verify basic signature params. Does not attempt sender recovery.
    pub fn verify_basic(&self, check_low_s: bool, chain_id: Option<u64>) -> Result<(), error::Error> {
        if self.is_unsigned() {
            return Err(parity_crypto::publickey::Error::InvalidSignature.into());
        }
        if check_low_s {
            self.check_low_s()?;
        }
        match (self.chain_id(), chain_id) {
            (None, _) => {},
            (Some(n), Some(m)) if n == m => {},
            _ => return Err(error::Error::InvalidChainId),
        };
        Ok(())
    }

    /// Try to verify transaction and recover sender.
    pub fn verify_unordered(self) -> Result<SignedTransaction, parity_crypto::publickey::Error> {
        SignedTransaction::new(self)
    }
}


pub mod signature {
    /// Adds chain id into v
    pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
        v + if let Some(n) = chain_id { 35 + n * 2 } else { 27 }
    }

    /// Returns refined v
    /// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
    pub fn check_replay_protection(v: u64) -> u8 {
        match v {
            v if v == 27 => 0,
            v if v == 28 => 1,
            v if v >= 35 => ((v - 1) % 2) as u8,
            _ => 4
        }
    }
}


pub fn should_agree_with_vitalik(raw_tx:&String,sender_addr:&String) {
    let  bytes: Vec<u8> = raw_tx.from_hex().unwrap();
    let signed = rlp::decode(&bytes).expect("decoding tx data failed");
    let signed = SignedTransaction::new(signed).unwrap();
    println!("Sender: {:?}", signed.sender());
    println!("ChainID: {:?}", signed.chain_id()); // "None" means the tx can be sent to both ETH and ETC ???
    assert_eq!(signed.sender(), Address::from_str(&sender_addr.as_str()[2..]).unwrap()); // Start with 0x...
    let (uv_tx, addr, pub_key) = signed.deconstruct();
    println!("Unverified Transacion:\nnonce: {}\ngas price: {}\ngas: {}",uv_tx.nonce,uv_tx.gas_price,uv_tx.gas);
    match uv_tx.action {
        Action::Create=>println!("no action"),
        Action::Call(data)=>println!("action: {:?}",data),
    }
    println!("data: {:?}\nvalue: {}\nv: {}\nr: {}\ns: {}\nhash: {:?}",uv_tx.data,uv_tx.value,uv_tx.v,uv_tx.r,uv_tx.s,uv_tx.hash);
    println!("Address: {:?}", addr);
    println!("Public key: {:?}", pub_key.unwrap());
}
pub fn should_agree_with_vitalik_withoutaddr(raw_tx:&String) {
    let  bytes: Vec<u8> = raw_tx.from_hex().unwrap();
    let signed = rlp::decode(&bytes).expect("decoding tx data failed");
    let signed = SignedTransaction::new(signed).unwrap();
    println!("Sender: {:?}", signed.sender());
    println!("ChainID: {:?}", signed.chain_id()); // "None" means the tx can be sent to both ETH and ETC ???
    let (uv_tx, addr, pub_key) = signed.deconstruct();
    println!("Unverified Transacion:\nnonce: {}\ngas price: {}\ngas: {}",uv_tx.nonce,uv_tx.gas_price,uv_tx.gas);
    match uv_tx.action {
        Action::Create=>println!("no action"),
        Action::Call(data)=>println!("action: {:?}",data),
    }
    println!("data: {:?}\nvalue: {}\nv: {}\nr: {}\ns: {}\nhash: {:?}",uv_tx.data,uv_tx.value,uv_tx.v,uv_tx.r,uv_tx.s,uv_tx.hash);
    println!("Address: {:?}", addr);
    println!("Public key: {:?}", pub_key.unwrap());
}

