# cmd-ethkey-bloom

//可用命令

// ./target/debug/bloom-cmd ethkey info 17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55

// ./target/debug/bloom-cmd ethkey info --brain "this is sparta"

// ./target/debug/bloom-cmd ethkey sign 17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55 bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987

// ./target/debug/bloom-cmd ethkey verify --public 689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987

// ./target/debug/bloom-cmd ethkey verify --public 689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec986

// ./target/debug/bloom-cmd ethkey verify --address 26d1ec50b4e62c1d1a40d16e7cacc6a6580757d5 --signature c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200 --message bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987

//  ./target/debug/bloom-cmd ethkey generate random

//  ./target/debug/bloom-cmd ethkey generate random --brain brain

//  ./target/debug/bloom-cmd ethkey generate prefix ff

//  ./target/debug/bloom-cmd ethkey generate prefix --brain 00cf

//  ./target/debug/bloom-cmd ethkey recover 00cf0cb028ae6f232eb39e8299157ddd321fd5c7 "angelfish ambulance rocking cushy liqueur unmoved ripcord numerator wrongful dwelling guiding sublime"

//  ./target/debug/bloom-cmd ethkey signtx --nonce 0 --to 26d1ec50b4e62c1d1a40d16e7cacc6a6580757d5 --value 0 --gas-price 10000 --gas 21240 --data 7f7465737432000000000000000000000000000000000000000000000000000000600057 --private-key 2a3526dd05ad2ebba87673f711ef8c336115254ef8fcd38c4d8166db9a8120e4 --chain-id 3

//  ./target/debug/bloom-cmd ethkey decodetx --raw-tx f8a80c8477359400825a109400e150d741eda1d49d341189cae4c08a73a49c9580b844a9059cbb00000000000000000000000085206176182d759c75a8ec4c884ac282f58d7b3d000000000000000000000000000000000000000000000005f68e8131ecf800001ba07d3db67dc644579d37c645456986a19b648a97d7deec79e23f452fcfdfdef197a063bcea7d043ab01cc8f5b9ecd6a87d8c9d373b422bedd05d772799241380d6f2 --sender-addr 0x8d1144b4c2b719a2618b9742364c8e1a8f925ae5
