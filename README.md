# opvault-demo

A minimal (and for test use only!) example wallet that makes use of 
[BIP-345 (`OP_VAULT`)](https://bip345.com) to provide reactive security with
vaults.

## Install and use

### The easy way

Install Docker and docker-compose somehow.

Then open two terminals. `cd` here, then run `source ./aliases.sh` in both.

You should see something like

```shell
OP_VAULT shortcuts
------------------

  build                     build docker containers
  start-bitcoin             run regtest bitcoind in the background
  demo [cmd ...]            run some command in the demo container
                              e.g. \`demo ./main.py watchtower\`
  bitcoin-cli [...]         run some bitcoin-cli command
  mine [num=1] [addr]       mine some blocks, maybe to an address

  vault-help                show this help


Getting started
---------------

Source this file:

  source ./aliases.sh

Build the containers and start bitcoind:

  build
  start-bitcoin

Generate a config and start the watchtower. This will run in one window, 
all other commands will happen in another:
  
  demo ./createconfig.py
  demo ./main.py

(then, in another window)

Fund the fee wallet:

  source ./aliases.sh
  bitcoin-cli createwallet fees
  mine 200 [fee address printed above]

Deposit to the vault:
  
  bitcoin-cli loadwallet fees  # if necessary
  mine 200  # mine another 200 blocks to the loaded wallet
  bitcoin-cli sendtoaddress [addr] [amt-btc]
  mine  # mine a block to actually process the deposit

Start a withdrawal:

  demo ./main.py withdraw bcrt1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8s7hfsm7 120000
  (you can use \`demo ./main.py withdraw --help\` too)

  mine  # call this until the trigger confirms and then "matures"
  mine  # mine once more to see the withdrawal confirm

Simulate a theft:

  demo ./main.py steal bcrt1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8s7hfsm7 12000
  [ see watchtower freak out ]
  demo ./main.py recover

```

### The no-docker way

Instructions probably incomplete.

```shell
# get OP_VAULT'd bitcoin
git clone https://github.com/jamesob/bitcoin.git -b 2023-02-opvault-inq
# [ build bitcoin ... ]
./src/bitcoind -regtest -fallbackfee=0.00001 -blockfilterindex=1

# cd back here
pip install -r requirements.txt
./main.py
```
