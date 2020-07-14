use crate::commands::account_cmd;
use ethereum_types::{H160, U256, H256};
use hex;
use structopt::StructOpt;
use std::fs::File;
use std::io::Read;
use std::str::FromStr; // !!! Necessary for H160::from_str(address).expect("...");
use std::collections::BTreeMap;

/*
target/debug/bloom-cmd contract deploy --from 0000000000000000000000000000000000000001  --value 0 --gas 100000 --gas-price 0 --code-file ./code-file
target/debug/bloom-cmd contract deploy --from 0000000000000000000000000000000000000001  --value 0 --gas 100000 --gas-price 0 --code 000000
target/debug/bloom-cmd contract call --from 0000000000000000000000000000000000000001  --to 0000000000000000000000000000000000000002 --value 0 --gas 100000 --gas-price 0 --data 000000
*/


#[derive(Debug, StructOpt, Clone)]
pub struct ContractCmd {
    #[structopt(subcommand)]
    cmd: Command
}

#[derive(StructOpt, Debug, Clone)]
enum Command {

    /// Deploy contract
    Deploy {
        /// The address which deploy contact
        #[structopt(long = "from")]
        from: String,

        /// The value to deposit in contract
        #[structopt(long = "value")]
        value: String,

        /// The gas limit for deploying contract
        #[structopt(long = "gas")]
        gas: u32,

        /// The gas price for deploying contract(Wei)
        #[structopt(long = "gas-price")]
        gas_price: String,

        /// The contract binary code
        #[structopt(long = "code")]
        code: Option<String>,

        /// The code file
        #[structopt(long = "code-file")]
        code_file: Option<String>,

    },

    /// Message call
    Call {
        /// The address which send messageCall
        #[structopt(long = "from")]
        from: String,

        /// The value (Wei) for messageCall
        #[structopt(long = "value")]
        value: String,

        /// The receiver address for messageCall
        #[structopt(long = "to")]
        to: String,

        /// The gas limit for messageCall
        #[structopt(long = "gas")]
        gas: u32,

        /// The gas price (Wei) for messageCall
        #[structopt(long = "gas-price")]
        gas_price: String,

        /// The input data for messageCall
        #[structopt(long = "data")]
        data: Option<String>,

        /// The input data file for messageCall
        #[structopt(long = "data-file")]
        data_file: Option<String>,

    }
}


impl ContractCmd {
    pub fn run(&self, mut backend: &str) {
        match &self.cmd {
            Command::Deploy {from,value,gas,gas_price,code,code_file} => {

                let from = H160::from_str(from).expect("From should be a valid address");
                let value = U256::from_dec_str(value.as_str()).expect("Value is invalid");
                let gas_price = U256::from_dec_str(gas_price.as_str()).expect("Gas price is invalid");
                let gas_limit = *gas;

                let mut contents = String::new();

                let code = match code {
                    Some(c) => {
                        Ok(c)
                    }
                    None => {
                        let ret = match code_file {
                            Some(file) => {
                                let mut f = File::open(file).expect(" code file not found");

                                f.read_to_string(&mut contents)
                                    .expect("something went wrong reading the file");
                                Ok(&contents)
                            }

                            None => {
                                Err(())
                            }
                        };
                        ret
                    }
                }.expect("--code or --code-file must be provided one of them ");
                println!("Deploy {:#?}", backend);
                println!(" from=={:#?}\n value=={:#?}\n gas=={:#?}\n gas_price=={:#?}\n code=={:#?}\n code_file=={:#?}\n",
                         from, value, gas, gas_price, code, code_file);
            }

            Command::Call {from,value,to,gas,gas_price,data,data_file} => {
                let from = H160::from_str(from).expect("From should be a valid address");
                let to = H160::from_str(to).expect("To should be a valid address");
                let value = U256::from_dec_str(value.as_str()).expect("Value is invalid");
                let gas_price = U256::from_dec_str(gas_price.as_str()).expect("Gas price is invalid");
                let gas_limit = *gas;

                let mut contents = String::new();

                let data = match data {
                    Some(d) => {
                        Ok(d)
                    }
                    None => {
                        let ret = match data_file {
                            Some(file) => {
                                let mut f = File::open(file).expect(" data file not found");

                                f.read_to_string(&mut contents)
                                    .expect("something went wrong reading the file");
                                Ok(&contents)
                            }

                            None => {
                                Err(())
                            }
                        };
                        ret
                    }
                }.unwrap_or(&contents);
                println!("Call {:#?}", backend);
                println!(" from=={:#?}\n to=={:#?}\n value=={:#?}\n gas=={:#?}\n gas_price=={:#?}\n data=={:#?}\n data_file=={:#?}\n",
                         from, to, value, gas, gas_price, data, data_file);
            }
        }
    }
}
