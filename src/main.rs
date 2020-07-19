mod commands;

use commands::Subcommand; //自定义
use structopt::StructOpt; //官方
#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[derive(Debug, StructOpt)]
pub struct Cli {
	#[structopt(subcommand)]
	pub subcmd: Option<Subcommand>,
}


fn main() {
	let cli = Cli::from_args();
	if let Some(ref subcmd) = cli.subcmd {
		subcmd.run();
	} else {
		println!("{:#?}", cli);
	}
}

/***

Cli {
    subcmd: Some(
        Contract(
            ContractCmd {
                cmd: Call {
                    from: "0000000000000000000000000000000000000001",
                    value: "0",
                    to: "0000000000000000000000000000000000000002",
                    gas: 100000,
                    gas_price: "0",
                    data: Some(
                        "000000",
                    ),
                    data_file: Some(
                        "abc.txt",
                    ),
                },
            },
        ),
    ),
}
##Subcommand: Contract##
Call "some backend args"
 from==0x0000000000000000000000000000000000000001
 to==0x0000000000000000000000000000000000000002
 value==0
 gas==100000
 gas_price==0
 data=="000000"
 data_file==Some(
    "abc.txt",
)
 ***/




