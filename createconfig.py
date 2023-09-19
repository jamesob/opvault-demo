#!/usr/bin/env python3
import json
import sys
import secrets
from pathlib import Path

from bip32 import BIP32
from clii import App

from main import VaultConfig, recoveryauth_phrase_to_key, WalletMetadata

cli = App('createconfig', description="Create a vault wallet configuration file.")


@cli.main
def main(
    spend_delay: int = 10,
    filepath: str = './config.json',
    secretspath: str = './secrets.json',
    trigger_seed_hex: str = '',
    recoveryauth_phrase: str = 'changeme2',
) -> None:
    """
    Create a new vault configuration. Don't use this with real money!

    Secrets are written into `secretspath` - obviously in production you'd do this
    differently, but the data in `config.json` isn't sensitive, whereas the stuff
    in `secrets.json` is.
    """
    if Path(filepath).exists():
        if input(f"Config already exists at {filepath} - overwrite? [yn] ") != 'y':
            sys.exit(1)

    # Not necessarily secure, don't use for real money, etc. etc.
    trigger_seed: bytes = secrets.token_bytes(32)
    if trigger_seed_hex:
        trigger_seed = bytes.fromhex(trigger_seed_hex)
    else:
        print(
            "!! using (probably insecure?) `secrets.token_bytes` for privkey -- "
            "don't use with real money")

    trig32 = BIP32.from_seed(trigger_seed)
    default_recovery32 = BIP32.from_seed(b"\x01")
    default_recovery_pubkey = default_recovery32.get_pubkey_from_path("m/0h/0")[1:]
    default_recoveryauth_pubkey = (
        recoveryauth_phrase_to_key(recoveryauth_phrase).get_pubkey().get_bytes()[1:])

    config = VaultConfig(
        spend_delay=spend_delay,
        recovery_pubkey=default_recovery_pubkey,
        recoveryauth_pubkey=default_recoveryauth_pubkey,
        trigger_xpub=trig32.get_xpub(),
    )
    WalletMetadata(config, filepath=Path(filepath)).save()

    secpath = Path(secretspath)
    secd = {}
    if secpath.exists():
        secd.update(json.loads(Path(secretspath).read_text()))

    secd[config.id] = {
        'trigger_xpriv': trig32.get_xpriv(),
        'recoveryauth_phrase': recoveryauth_phrase,
    }
    secpath.write_text(json.dumps(secd, indent=2))


if __name__ == "__main__":
    cli.run()
