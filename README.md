# opvault-demo

A minimal (and for test use only!) example wallet that makes use of 
[BIP-345 (`OP_VAULT`)](https://bip345.com) to provide reactive security with
vaults.

## Install and use

```shell
# get OP_VAULT'd bitcoin
git clone https://github.com/jamesob/bitcoin.git -b 2023-02-opvault-inq
./src/bitcoind -regtest -fallbackfee=0.00001 -blockfilterindex=1

# cd back here
pip install -e .
./main.py
```

TODO: Docker option?
