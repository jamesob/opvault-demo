#!/bin/bash

build() {
  if [ "$(id -u)" != "1000" ]; then
    echo "!! you may have permission problems - uncomment the bitcoin: build:"
    echo "  section in docker-compose.yml!"
    echo
  fi
  mkdir -p bitcoin-datadir
  docker-compose build --build-arg UID=$(id -u) --build-arg GID=$(id -g)
}

start-bitcoin() {
  docker-compose up -d bitcoin
  docker-compose ps
}

demo() {
  docker-compose run --rm demo $@
}

bitcoin-cli() {
  docker-compose exec bitcoin bitcoin-cli -regtest $@
}

check-bitcoin-up() {
  docker-compose ps | grep Up | grep bitcoin_ >/dev/null
}

mine() {
  NUM_BLOCKS=${1}
  TO_ADDRESS=${2}

  check-bitcoin-up || start-bitcoin

  if [ -z "${TO_ADDRESS}" ]; then
    bitcoin-cli -generate $@
  else
    bitcoin-cli generatetoaddress $@
  fi
}

VAULT_GUIDE=$(cat << EOF

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

EOF
)

vault-help() {
  echo $VAULT_GUIDE
}

vault-help
