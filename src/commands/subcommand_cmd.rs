use ethereum_types::{H160, U256, H256};
use hex;
use web3;
use structopt::StructOpt;
use std::fs::File;
use std::str::FromStr; // !!! Necessary for H160::from_str(address).expect("...");
use std::collections::BTreeMap;
use parity_crypto::publickey::{KeyPair, Random, Error as EthkeyError, Generator, sign, verify_public, verify_address};
use rustc_hex::{FromHex, FromHexError};
use std::num::ParseIntError;
use std::{env, fmt, process, io, sync};
use docopt::Docopt;
use parity_crypto::Keccak256;
use parity_wordlist;
use parity_bytes::ToPretty;
use threadpool;
mod brain;
use brain::Brain;
mod brian_prefix;
use brian_prefix::BrainPrefix;
mod prefix;
use prefix::Prefix;
mod brain_recover;
use brain_recover::PhrasesIterator;
mod raw_transaction;
use raw_transaction::RawTransaction;

const USAGE: &'static str = r#"
OpenEthereum keys generator.
  Copyright 2015-2020 Parity Technologies (UK) Ltd.

Usage:
    ethkey info <secret-or-phrase> [options]
    ethkey generate random [options]
    ethkey generate prefix <prefix> [options]
    ethkey sign <secret> <message>
    ethkey verify public <public> <signature> <message>
    ethkey verify address <address> <signature> <message>
    ethkey recover <address> <known-phrase>
    ethkey [-h | --help]

Options:
    -h, --help         Display this message and exit.
    -s, --secret       Display only the secret key.
    -p, --public       Display only the public key.
    -a, --address      Display only the address.
    -b, --brain        Use parity brain wallet algorithm. Not recommended.

Commands:
    info               Display public key and address of the secret.
    generate random    Generates new random Ethereum key.
    generate prefix    Random generation, but address must start with a prefix ("vanity address").
    sign               Sign message using a secret key.
    verify             Verify signer of the signature by public key or address.
    recover            Try to find brain phrase matching given address from partial phrase.
"#;
#[derive(Debug, Deserialize)]
struct Args {
    cmd_info: bool,
    cmd_generate: bool,
    cmd_random: bool,
    cmd_prefix: bool,
    cmd_sign: bool,
    cmd_verify: bool,
    cmd_public: bool,
    cmd_address: bool,
    cmd_recover: bool,
    arg_prefix: String,
    arg_secret: String,
    arg_secret_or_phrase: String,
    arg_known_phrase: String,
    arg_message: String,
    arg_public: String,
    arg_address: String,
    arg_signature: String,
    flag_secret: bool,
    flag_public: bool,
    flag_address: bool,
    flag_brain: bool,
}

enum DisplayMode{
    KeyPair,
    Secret,
    Public,
    Address,
}
impl DisplayMode{
    fn new(args: &Args) -> Self {
        if args.flag_secret {
            DisplayMode::Secret
        } else if args.flag_public {
            DisplayMode::Public
        } else if args.flag_address {
            DisplayMode::Address
        } else {
            DisplayMode::KeyPair
        }
    }
}
#[derive(Debug)]
enum Error{
    Ethkey(EthkeyError),
    FromHex(FromHexError),
    ParseInt(ParseIntError),
    Docopt(docopt::Error),
    Io(io::Error),
}
impl From<EthkeyError> for Error {
    fn from(err: EthkeyError) -> Self {
        Error::Ethkey(err)
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Error::FromHex(err)
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Error::ParseInt(err)
    }
}

impl From<docopt::Error> for Error {
    fn from(err: docopt::Error) -> Self {
        Error::Docopt(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Ethkey(ref e) => write!(f, "{}", e),
            Error::FromHex(ref e) => write!(f, "{}", e),
            Error::ParseInt(ref e) => write!(f, "{}", e),
            Error::Docopt(ref e) => write!(f, "{}", e),
            Error::Io(ref e) => write!(f, "{}", e),
        }
    }
}
fn execute<S, I>(command: I) -> Result<String, Error> where I: IntoIterator<Item=S>, S: AsRef<str> {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(command).deserialize())?;
    println!("{:#?}",args);
    return if args.cmd_info {
        let display_mode = DisplayMode::new(&args);

        let result = if args.flag_brain {
            let phrase = args.arg_secret_or_phrase;
            let phrase_info = validate_phrase(&phrase);
            let keypair = Brain::new(phrase).generate();
            (keypair, Some(phrase_info))
        } else {
            let secret = args.arg_secret_or_phrase.parse().map_err(|_| EthkeyError::InvalidSecretKey)?;
            (KeyPair::from_secret(secret)?, None)
        };
        println!("{:#?}",result);
        Ok(display(result, display_mode))
    } else if args.cmd_sign {
        let secret = args.arg_secret.parse().map_err(|_| EthkeyError::InvalidSecretKey)?;
        let message = args.arg_message.parse().map_err(|_| EthkeyError::InvalidMessage)?;
        let signature = sign(&secret, &message)?;
        Ok(format!("{}", signature))
    }else if args.cmd_verify{
        let signature = args.arg_signature.parse().map_err(|_| EthkeyError::InvalidSignature)?;
        let message = args.arg_message.parse().map_err(|_| EthkeyError::InvalidMessage)?;
        let ok = if args.cmd_public {
            let public = args.arg_public.parse().map_err(|_| EthkeyError::InvalidPublicKey)?;
            verify_public(&public, &signature, &message)?
        } else if args.cmd_address {
            let address = args.arg_address.parse().map_err(|_| EthkeyError::InvalidAddress)?;
            verify_address(&address, &signature, &message)?
        } else {
            return Ok(format!("{}", USAGE))
        };
        Ok(format!("{}", ok))
    }else if args.cmd_generate{
        let display_mode = DisplayMode::new(&args);
        let result = if args.cmd_random {
            if args.flag_brain {
                let mut brain = BrainPrefix::new(vec![0], usize::max_value(), BRAIN_WORDS);
                let keypair = brain.generate()?;
                let phrase = format!("recovery phrase: {}", brain.phrase());
                (keypair, Some(phrase))
            } else {
                (Random.generate(), None)
            }
        } else if args.cmd_prefix {
            let prefix: Vec<_> = args.arg_prefix.from_hex()?;
            let brain = args.flag_brain;
            in_threads(move || {
                let iterations = 1024;
                let prefix = prefix.clone();
                move || {
                    let prefix = prefix.clone();
                    let res = if brain {
                        let mut brain = BrainPrefix::new(prefix, iterations, BRAIN_WORDS);
                        let result = brain.generate();
                        let phrase = format!("recovery phrase: {}", brain.phrase());
                        result.map(|keypair| (keypair, Some(phrase)))
                    } else {
                        let result = Prefix::new(prefix, iterations).generate();
                        result.map(|res| (res, None))
                    };
                    Ok(res.map(Some).unwrap_or(None))
                }
            })?
        } else {
            return Ok(format!("{}", USAGE))
        };
        Ok(display(result, display_mode))
    }else if args.cmd_recover {
        let display_mode = DisplayMode::new(&args);
        let known_phrase = args.arg_known_phrase;
        let address = args.arg_address.parse().map_err(|_| EthkeyError::InvalidAddress)?;
        let (phrase, keypair) = in_threads(move || {
            let mut it = brain_recover::PhrasesIterator::from_known_phrase(&known_phrase, BRAIN_WORDS);
            move || {
                let mut i = 0;
                while let Some(phrase) = it.next() {
                    i += 1;

                    let keypair = Brain::new(phrase.clone()).generate();
                    if keypair.address() == address {
                        return Ok(Some((phrase, keypair)))
                    }

                    if i >= 1024 {
                        return Ok(None)
                    }
                }

                Err(EthkeyError::Custom("Couldn't find any results.".into()))
            }
        })?;
        Ok(display((keypair, Some(phrase)), display_mode))
    }else {
        Ok(format!("{}", USAGE))
    }
}

const BRAIN_WORDS:usize=12;
fn validate_phrase(phrase: &str) -> String {
    match Brain::validate_phrase(phrase, BRAIN_WORDS) {
        Ok(()) => format!("The recovery phrase looks correct.\n"),
        Err(err) => format!("The recover phrase was not generated by Parity: {}", err)
    }
}
fn display(result: (KeyPair, Option<String>), mode: DisplayMode) -> String {
    let keypair = result.0;
    println!("{:#?}",keypair);
    match mode {
        DisplayMode::KeyPair => match result.1 {
            Some(extra_data) => format!("{}\n{}", extra_data, keypair),
            None => format!("{}", keypair)
        },
        DisplayMode::Secret => format!("{:x}", keypair.secret()),
        DisplayMode::Public => format!("{:x}", keypair.public()),
        DisplayMode::Address => format!("{:x}", keypair.address()),
    }
}
fn in_threads<F, X, O>(prepare: F) -> Result<O, EthkeyError> where
    O: Send + 'static,
    X: Send + 'static,
    F: Fn() -> X,
    X: FnMut() -> Result<Option<O>, EthkeyError>,
{
    let pool = threadpool::Builder::new().build();

    let (tx, rx) = sync::mpsc::sync_channel(1);
    let is_done = sync::Arc::new(sync::atomic::AtomicBool::default());

    for _ in 0..pool.max_count() {
        let is_done = is_done.clone();
        let tx = tx.clone();
        let mut task = prepare();
        pool.execute(move || {
            loop {
                if is_done.load(sync::atomic::Ordering::SeqCst) {
                    return;
                }

                let res = match task() {
                    Ok(None) => continue,
                    Ok(Some(v)) => Ok(v),
                    Err(err) => Err(err),
                };

                // We are interested only in the first response.
                let _ = tx.send(res);
            }
        });
    }

    if let Ok(solution) = rx.recv() {
        is_done.store(true, sync::atomic::Ordering::SeqCst);
        return solution;
    }

    Err(EthkeyError::Custom("No results found.".into()))
}

fn sign_tx(nonce:&String,to:&String,value:&String,gas_price:&String,gas:&String,data:&String,private_key:&String,chain_id:&String){
    let nonce=nonce.to_string().parse::<u128>().unwrap();
    let to=to.to_string().parse::<u64>().unwrap();
    let value=value.to_string().parse::<u128>().unwrap();
    let gas_price=gas_price.to_string().parse::<u128>().unwrap();
    let gas=gas.to_string().parse::<u128>().unwrap();
    let data=data.to_string();
    let private_key=private_key.to_string();
    let chain_id=chain_id.to_string().parse::<u32>().unwrap();
    let tx = raw_transaction::RawTransaction {
        nonce: web3::types::U256::from(nonce),
        to: Some(web3::types::H160::from_low_u64_be(to)),
        value: web3::types::U256::from(value),
        gas_price: web3::types::U256::from(gas_price),
        gas: web3::types::U256::from(gas),
        data: hex::decode(
            data
        ).unwrap(),
    };
    let mut data: [u8; 32] = Default::default();
    data.copy_from_slice(&hex::decode(
        private_key
    ).unwrap());
    let private_key = web3::types::H256(data);
    let raw_rlp_bytes = tx.sign(&private_key, &chain_id);
    println!("{:?}",raw_rlp_bytes);
}

#[derive(Debug, StructOpt, Clone)]
pub struct EthkeyCmd {
    #[structopt(subcommand)]
    cmd: Command
}

#[derive(StructOpt, Debug, Clone)]
enum Command {
    ///Info Eth_keyCmd
    Info{
        #[structopt(default_value="Info is None!")]
        info:String,
        #[structopt(long = "brain",default_value="Brain is None!")]
        brain :String,
    },
    Sign{
        secret:String,
        message:String,
    },
    Verify{
        #[structopt(long = "public",default_value="No verify for public!")]
        public:String,
        #[structopt(long = "address",default_value="No verify for address!")]
        address:String,
        #[structopt(long = "signature")]
        signature:String,
        #[structopt(long = "message")]
        message:String,
    },
    Generate{
        method:String,
        #[structopt(long = "brain",default_value="No brain!")]
        brain:String,
        #[structopt(default_value="nothing")]
        prefix:String,
    },
    Recover{
        address:String,
        phrase:String,
    },
    Signtx{
        #[structopt(long = "nonce")]
        nonce:String,
        #[structopt(long = "to")]
        to:String,
        #[structopt(long = "value")]
        value:String,
        #[structopt(long = "gas-price")]
        gas_price:String,
        #[structopt(long = "gas")]
        gas:String,
        #[structopt(long = "data")]
        data:String,
        #[structopt(long = "private-key")]
        private_key:String,
        #[structopt(long = "chain-id")]
        chain_id:String,
    },
}

//  ./target/debug/bloom-cmd ethkey info 17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55
//  ./target/debug/bloom-cmd ethkey info --brain "this is sparta"
//  ./target/debug/bloom-cmd ethkey sign 17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55 bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987
//  ./target/debug/bloom-cmd ethkey verify --public 689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987
//  ./target/debug/bloom-cmd ethkey verify --public 689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec986
//  ./target/debug/bloom-cmd ethkey verify --address 26d1ec50b4e62c1d1a40d16e7cacc6a6580757d5 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987
//  ./target/debug/bloom-cmd ethkey generate random
//  ./target/debug/bloom-cmd ethkey generate random --brain brain
//  ./target/debug/bloom-cmd ethkey generate prefix ff
//  ./target/debug/bloom-cmd ethkey generate prefix --brain 00cf
//  ./target/debug/bloom-cmd ethkey recover 00cf0cb028ae6f232eb39e8299157ddd321fd5c7 "angelfish ambulance rocking cushy liqueur unmoved ripcord numerator wrongful dwelling guiding sublime"
//  ./target/debug/bloom-cmd ethkey signtx --nonce 0 --to 0 --value 0 --gas-price 10000 --gas 21240 --data 7f7465737432000000000000000000000000000000000000000000000000000000600057 --private-key 2a3526dd05ad2ebba87673f711ef8c336115254ef8fcd38c4d8166db9a8120e4 --chain-id 3
impl EthkeyCmd {
    pub fn run(&self, mut backend: &str) {
        match &self.cmd {
            Command::Info {info,brain} => {
                if (brain.to_string()=="Brain is None!".to_string()){
                    let command = vec!["ethkey", "info", &info.to_string()]
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<String>>();
                    let result=execute(command);
                    println!("Deploy {:#?}", backend);
                    println!("{}",result.unwrap());
                }
                else{
                    let command = vec!["ethkey", "info", "--brain", &brain.to_string()]
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<String>>();
                    let result=execute(command);
                    println!("Deploy {:#?}", backend);
                    println!("{}",result.unwrap());
                }
            }
            Command::Sign{secret,message}=>{
                let command = vec!["ethkey", "sign", &secret.to_string(),&message.to_string()]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result=execute(command);
                println!("Deploy {:#?}", backend);
                println!("{}",result.unwrap());
            }
            Command::Verify{public,address,signature,message}=>{
                if (address.to_string()=="No verify for address!".to_string()){
                    let command = vec!["ethkey","verify" ,"public", &public.to_string(), &signature.to_string(), &message.to_string()]
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<String>>();
                    let result=execute(command);
                    println!("Deploy {:#?}", backend);
                    println!("{}",result.unwrap());
                }
                else{
                    let command = vec!["ethkey","verify" ,"address", &address.to_string(), &signature.to_string(), &message.to_string()]
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<String>>();
                    let result=execute(command);
                    println!("Deploy {:#?}", backend);
                    println!("{}",result.unwrap());
                }
            }
            Command::Generate{method,brain,prefix}=>{
                if(method.to_string()=="random".to_string()){
                    if(brain.to_string()=="No brain!".to_string()){
                        let command = vec!["ethkey","generate","random"]
                            .into_iter()
                            .map(Into::into)
                            .collect::<Vec<String>>();
                        let result=execute(command);
                        println!("Deploy {:#?}", backend);
                        println!("{}",result.unwrap());
                    }else{
                        let command = vec!["ethkey","generate","random","--brain"]
                            .into_iter()
                            .map(Into::into)
                            .collect::<Vec<String>>();
                        let result=execute(command);
                        println!("Deploy {:#?}", backend);
                        println!("{}",result.unwrap());
                    }
                }else{
                    if(brain.to_string()=="No brain!".to_string()){
                        let command = vec!["ethkey","generate","prefix",&prefix.to_string()]
                            .into_iter()
                            .map(Into::into)
                            .collect::<Vec<String>>();
                        let result=execute(command);
                        println!("Deploy {:#?}", backend);
                        println!("{}",result.unwrap());
                    }else{
                        let command = vec!["ethkey","generate","prefix","--brain",&brain.to_string()]
                            .into_iter()
                            .map(Into::into)
                            .collect::<Vec<String>>();
                        let result=execute(command);
                        println!("Deploy {:#?}", backend);
                        println!("{}",result.unwrap());
                    }
                }
            }
            Command::Recover{address,phrase}=>{
                let command = vec!["ethkey", "recover" ,&address.to_string(),&phrase.to_string()]
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<String>>();
                let result=execute(command);
                println!("Deploy {:#?}", backend);
                println!("{}",result.unwrap());
            }
            Command::Signtx{nonce,to,value,gas_price,gas,data,private_key,chain_id}=>{
                sign_tx(nonce,to,value,gas_price,gas,data,private_key,chain_id);
            }
        }
    }
}
