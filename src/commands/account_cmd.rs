use structopt::StructOpt;
use ethereum_types::{H160, H256, U256};
use std::fmt;
use std::collections::BTreeMap;
use std::str::FromStr; // !!! Necessary for H160::from_str(address).expect("...");

// target/debug/bloom-cmd account create --address 59a5208b32e627891c389ebafc644145224006e8 --value 10 --nonce 12
// target/debug/bloom-cmd account query --address 59a5208b32e627891c389ebafc644145224006e8
// target/debug/bloom-cmd account query --address 59a5208b32e627891c389ebafc644145224006e8 --storage-trie

#[derive(Debug, Clone, StructOpt)]
pub struct AccountCmd {
	#[structopt(subcommand)]
	cmd: Command
}

#[derive(Debug, Clone, StructOpt)]
enum Command {

	/// Query external or contract account information
	Query {
		/// External address or contract address
		#[structopt(long = "address")]
		address: String,
		/// Flag whether show the storage trie
		#[structopt(long = "storage-trie")]
		storage_trie:bool
	},

	/// Create external account
	Create {
		/// External address will be created
		#[structopt(long = "address")]
		address: String,
		/// Value (Wei) for the given address,  default 1 ether (18 zeros)
		#[structopt(long = "value", default_value = "1000000000000000000")]
		value: String,
		/// Nonce for the given address, default 0
		#[structopt(long = "nonce", default_value = "0")]
		nonce: String,
	},

	/// Modify external account
	Modify {
		/// External address will be modified
		#[structopt(long = "address")]
		address: String,
		/// Value (Wei) for the given address
		#[structopt(long = "value")]
		value: String,
		/// Nonce for the given address
		#[structopt(long = "nonce")]
		nonce: String,
	},

	/// Transfer value between two external accounts
	Transfer {
		/// The address from which transfer from
		#[structopt(long = "from")]
		from: String,
		/// The address from which transfer to
		#[structopt(long = "to")]
		to: String,
		/// Value for transfer
		#[structopt(long = "value")]
		value: String,
	},

	///Test for cmd
	Test_one{
		#[structopt(short="h",long="foulish")]
		foo:String,
	}
}


impl AccountCmd {
	pub fn run(&self, mut backend: &str) {
		match &self.cmd {
			Command::Query {address, storage_trie} => {

				println!("Query {:#?}", backend);
				println!(" address=={:#?}\n storage_trie=={:#?}\n", address, storage_trie);
			},

			Command::Create {address,value,nonce} => {
				let from = H160::from_str(address).expect("--address argument must be a valid address");
				let value = U256::from_dec_str(value.as_str()).expect("--value argument must be a valid number");
				let nonce = U256::from_dec_str(nonce.as_str()).expect("--nonce argument must be a valid number");
				println!("Create {:#?}", backend);
				println!(" address=={:#?}\n value=={:#?}\n nonce=={:#?}\n", address, value, nonce);

			},

			Command::Modify {address, value, nonce} => {
				let from = H160::from_str(address).expect("--address argument must be a valid address");
				let value = U256::from_dec_str(value.as_str()).expect("--value argument must be a valid number");
				let nonce = U256::from_dec_str(nonce.as_str()).expect("--nonce argument must be a valid number");
				println!("Modify {:#?}", backend);
				println!(" address=={:#?}\n value=={:#?}\n nonce=={:#?}\n", address, value, nonce);

			},

			Command::Transfer {from, to, value} => {

				let from = H160::from_str(from).expect("--from argument must be a valid address");
				let to  = H160::from_str(to).expect("--to argument must be a valid address");
				let value = U256::from_dec_str(value.as_str()).expect("--value argument must be a valid number");

				println!("Transfer {:#?}", backend);
				println!(" from=={:#?}\n to=={:#?}\n value=={:#?}\n", from, to, value);
			},
			Command::Test_one{foo}=> {
				let foo=U256::from_dec_str(foo.as_str()).expect("--foo argument must be a value");
				println!("Test_one {:#?}",backend);
				println!("foo = {:#?}",foo);
			}
		}
	}
}
