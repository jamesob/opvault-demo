#!/usr/bin/env python3
import os
import sys
import random
import json
import time
import typing as t
from functools import cached_property
from dataclasses import dataclass, field
from pathlib import Path

from clii import App
from bip32 import BIP32

import verystable
from verystable.script import CTransaction, TaprootInfo
from verystable import core, wallet
from verystable.rpc import BitcoinRPC
from verystable.core import script
from verystable.core.script import CScript
from verystable.core.messages import COutPoint, CTxOut, CTxIn

import logging

loglevel = "DEBUG" if os.environ.get("DEBUG") else "INFO"
try:
    # If `rich` is installed, use pretty logging.
    from rich.logging import RichHandler
    from rich import print

    logging.basicConfig(level=loglevel, datefmt="[%X]", handlers=[RichHandler()])
except ImportError:
    logging.basicConfig(level=loglevel)

log = logging.getLogger("opvault")


verystable.softforks.activate_bip345_vault()
verystable.softforks.activate_bip119_ctv()


@dataclass
class VaultConfig:
    spend_delay: int
    recovery_pubkey: bytes
    trigger_seed: bytes
    recoveryauth_seed: bytes
    network: str = "regtest"

    @cached_property
    def recov_taproot_info(self) -> TaprootInfo:
        return script.taproot_construct(self.recovery_pubkey[1:])

    @cached_property
    def recov_address(self) -> str:
        return core.address.output_key_to_p2tr(self.recov_taproot_info.output_pubkey)

    @cached_property
    def recovauth_pubkey(self) -> bytes:
        b32 = BIP32.from_seed(self.recoveryauth_seed)
        return b32.get_pubkey_from_path("m/0h/0")[1:]

    @cached_property
    def recovauth_privkey(self) -> bytes:
        b32 = BIP32.from_seed(self.recoveryauth_seed)
        return b32.get_privkey_from_path("m/0h/0")

    def get_trigger_xonly_pubkey(self, num: int) -> bytes:
        b32 = BIP32.from_seed(self.trigger_seed)
        got = b32.get_pubkey_from_path(f"m/0h/{num}")
        assert len(got) == 33
        return got[1:]

    def get_trigger_privkey(self, num: int) -> bytes:
        b32 = BIP32.from_seed(self.trigger_seed)
        return b32.get_privkey_from_path(f"m/0h/{num}")

    def get_spec_for_vault_num(self, num: int) -> "VaultSpec":
        return VaultSpec(
            vault_num=num,
            spend_delay=self.spend_delay,
            trigger_pubkey=self.get_trigger_xonly_pubkey(num),
            recovery_pubkey=self.recov_taproot_info.output_pubkey,
            recovery_spk=self.recov_taproot_info.scriptPubKey,
            recovauth_pubkey=self.recovauth_pubkey,
        )


@dataclass
class VaultSpec:
    """Manages script constructions and parameters for a particular vaulted coin."""

    # Incrementing ID that determines trigger key paths.
    vault_num: int
    spend_delay: int
    trigger_pubkey: bytes
    recovery_pubkey: bytes
    recovery_spk: CScript
    recovauth_pubkey: bytes

    # Determines the behavior of the withdrawal process.
    leaf_update_script_body = (
        script.OP_CHECKSEQUENCEVERIFY,
        script.OP_DROP,
        script.OP_CHECKTEMPLATEVERIFY,
    )

    def __post_init__(self):
        assert len(self.trigger_pubkey) == 32
        assert len(self.recovery_pubkey) == 32
        assert len(self.recovauth_pubkey) == 32

        recov_hash = recovery_spk_tagged_hash(self.recovery_spk)

        self.recovery_script = CScript(
            [
                self.recovauth_pubkey,
                script.OP_CHECKSIGVERIFY,
                recov_hash,
                script.OP_VAULT_RECOVER,
            ]
        )

        self.trigger_script = CScript(
            [
                self.trigger_pubkey,
                script.OP_CHECKSIGVERIFY,
                self.spend_delay,
                2,
                CScript(self.leaf_update_script_body),
                script.OP_VAULT,
            ]
        )
        self.taproot_info = script.taproot_construct(
            self.recovery_pubkey,
            scripts=[
                ("recover", self.recovery_script),
                ("trigger", self.trigger_script),
            ],
        )

        self.output_pubkey = self.taproot_info.output_pubkey
        self.address = core.address.output_key_to_p2tr(self.output_pubkey)


@dataclass
class TriggerSpec:
    """Manages script constructions and parameters for a triggered vault coin."""

    vault_specs: list[VaultSpec]
    destination_ctv_hash: bytes
    trigger_value_sats: int

    def __post_init__(self):
        specs = self.vault_specs
        vault_spec = specs[0]

        def assert_specs_have_same(key):
            assert len(set(getattr(spec, key) for spec in specs)) == 1

        assert_specs_have_same("spend_delay")
        assert_specs_have_same("leaf_update_script_body")
        assert_specs_have_same("recovery_script")
        assert_specs_have_same("recovery_pubkey")

        self.withdrawal_script = CScript(
            [
                self.destination_ctv_hash,
                vault_spec.spend_delay,
                *vault_spec.leaf_update_script_body,
            ]
        )
        self.recovery_script = vault_spec.recovery_script

        self.taproot_info = script.taproot_construct(
            vault_spec.recovery_pubkey,
            scripts=[
                ("recover", self.recovery_script),
                ("withdraw", self.withdrawal_script),
            ],
        )

        self.scriptPubKey = self.taproot_info.scriptPubKey
        self.address = self.taproot_info.p2tr_address

    @cached_property
    def spend_delay(self) -> int:
        return self.vault_specs[0].spend_delay

    @cached_property
    def withdrawal_witness(self) -> list[bytes | CScript]:
        """Bottom of witness stack when spending a trigger to final withdrawal."""
        return [
            self.taproot_info.leaves["withdraw"].script,
            self.taproot_info.controlblock_for_script_spend("withdraw"),
        ]

    @cached_property
    def recover_wit_fragment(self) -> list[bytes | CScript]:
        """Bottom of witness stack when spending a trigger into a recovery."""
        return [
            self.taproot_info.leaves["recover"].script,
            self.taproot_info.controlblock_for_script_spend("recover"),
        ]


def recovery_spk_tagged_hash(script: CScript) -> bytes:
    ser = core.messages.ser_string(script)
    return core.key.TaggedHash("VaultRecoverySPK", ser)


def txid_to_int(txid: str) -> int:
    return int.from_bytes(bytes.fromhex(txid), byteorder="big")


def btc_to_sats(btc) -> int:
    return int(btc * core.messages.COIN)


@dataclass(frozen=True)
class Outpoint:
    txid: str
    n: int

    def __str__(self):
        return f"{self.txid}:{self.n}"


@dataclass(frozen=True)
class Utxo:
    outpoint: Outpoint
    address: str
    value_sats: int
    height: int

    @cached_property
    def scriptPubKey(self) -> CScript:
        return core.address.address_to_scriptpubkey(self.address)

    @cached_property
    def coutpoint(self) -> COutPoint:
        return COutPoint(txid_to_int(self.outpoint.txid), self.outpoint.n)

    @cached_property
    def output(self) -> CTxOut:
        return CTxOut(nValue=self.value_sats, scriptPubKey=self.scriptPubKey)

    @cached_property
    def as_txin(self) -> CTxIn:
        return CTxIn(self.coutpoint)

    @property
    def outpoint_str(self) -> str:
        return str(self.outpoint)


@dataclass(frozen=True)
class VaultUtxo(Utxo):
    config: VaultConfig

    vault_spec: VaultSpec | None = None
    trigger_spec: TriggerSpec | None = None

    def __post_init__(self):
        assert self.vault_spec or self.trigger_spec

    def get_taproot_info(self):
        """Return the most relevant taproot info."""
        spec = self.trigger_spec or self.vault_spec
        return spec.taproot_info


@dataclass(frozen=True)
class VaultEvent:
    height: int
    txid: str
    utxos: list[VaultUtxo]
    value_sats: int


@dataclass(frozen=True)
class DepositEvent(VaultEvent):
    pass


@dataclass(frozen=True)
class TriggerEvent(VaultEvent):
    pass


@dataclass(frozen=True)
class RecoverEvent(VaultEvent):
    pass


@dataclass(frozen=True)
class WithdrawalEvent(VaultEvent):
    pass


@dataclass
class Spend:
    spent_utxo: Utxo
    height: int
    tx: dict

    def __repr__(self) -> str:
        return (
            f"Spend(amt={self.spent_utxo.value_sats} "
            f"from_addr={self.spent_utxo.address}, height={self.height})"
        )


def get_history(
    rpc: BitcoinRPC,
    addr_watchlist: t.Iterable[str],
) -> tuple[set[Utxo], list[Spend]]:
    utxos: set[Utxo] = set()
    spent: list[Spend] = []
    scanarg = [f"addr({addr})" for addr in addr_watchlist]

    got = rpc.scanblocks("start", scanarg)
    assert "relevant_blocks" in got

    heights_and_blocks = []
    for hash in set(got["relevant_blocks"]):
        block = rpc.getblock(hash, 2)
        heights_and_blocks.append((block["height"], block))

    outpoint_to_utxo: dict[Outpoint, Utxo] = {}
    txids_to_watch: set[str] = set()

    for height, block in sorted(heights_and_blocks):
        for tx in block["tx"]:
            # Detect new utxos
            for vout in tx["vout"]:
                if (addr := vout.get("scriptPubKey", {}).get("address")) and (
                    addr in addr_watchlist
                ):
                    op = Outpoint(tx["txid"], vout["n"])
                    utxo = Utxo(op, addr, btc_to_sats(vout["value"]), height)
                    outpoint_to_utxo[op] = utxo
                    txids_to_watch.add(tx["txid"])
                    utxos.add(utxo)
                    log.info("found utxo (%s): %s", addr, utxo)

            # Detect spends
            for vin in filter(lambda vin: "txid" in vin, tx["vin"]):
                spent_txid = vin["txid"]
                if spent_txid not in txids_to_watch:
                    continue

                op = Outpoint(spent_txid, vin.get("vout"))

                if not (spent_utxo := outpoint_to_utxo.get(op)):
                    continue

                log.info("found spend of utxo %s", spent_utxo)
                spent.append(Spend(spent_utxo, height, tx))
                utxos.remove(spent_utxo)
                outpoint_to_utxo.pop(op)

    return utxos, spent


@dataclass
class ChainMonitor:
    config: VaultConfig
    rpc: BitcoinRPC
    addr_to_vault_spec: dict[str, VaultSpec] = field(default_factory=dict)
    outpoint_to_utxo: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    outpoint_to_trigger_tx: dict[Outpoint, dict] = field(default_factory=dict)
    last_height_scanned: int = 0
    history: list[VaultEvent] = field(default_factory=list)

    def __post_init__(self):
        default_gap_limit = 50
        for i in range(default_gap_limit):
            spec = self.config.get_spec_for_vault_num(i)
            self.addr_to_vault_spec[spec.address] = spec

    @property
    def vault_and_trigger_txids(self):
        """
        txids that contain vaults that are either unspent or in the trigger process.

        In other words, any vault not yet recovered.
        """
        txids = {outpoint.txid for outpoint in self.outpoint_to_utxo}
        txids.update({outpoint.txid for outpoint in self.outpoint_to_trigger_tx})
        return txids

    def rescan(self):
        relevant_blocks = set()
        last_height = None

        for addr in self.addr_to_vault_spec:
            got = self.rpc.scanblocks(
                "start", [f"addr({addr})"], self.last_height_scanned + 1
            )

            if last_height is None or got["to_height"] < last_height:
                last_height = got["to_height"]

            if blockhashes := got["relevant_blocks"]:
                relevant_blocks.update(blockhashes)
                log.debug("saw relevant blocks for %s: %s", addr, blockhashes)

        heights_and_blocks = []
        for hash in relevant_blocks:
            got = self.rpc.getblock(hash, 2)
            heights_and_blocks.append((got["height"], got))

        # Replay blocks in ascending order, updating wallet state.
        for height, block in sorted(heights_and_blocks):
            for tx in block["tx"]:

                def log_history(EventType, utxo):
                    self.history.append(
                        EventType(height, tx["txid"], [utxo], utxo.value_sats)
                    )

                def find_vout_with_address(findaddr: str) -> dict | None:
                    for v in tx["vout"]:
                        if findaddr == v.get("scriptPubKey", {}).get("address"):
                            return v
                    return None

                # Detect vault movements
                for vin in filter(lambda vin: "txid" in vin, tx["vin"]):
                    spent_txid = vin["txid"]
                    if spent_txid not in self.vault_and_trigger_txids:
                        continue

                    op = Outpoint(spent_txid, vin.get("vout"))

                    if spent := self.outpoint_to_utxo.get(op):
                        if find_vout_with_address(self.config.recov_address):
                            log.info("found recovery of untriggered vault %s", spent)
                            log_history(RecoverEvent, spent)
                        else:
                            log.info("found spend of vault %s", spent)
                            log_history(TriggerEvent, spent)
                            self.outpoint_to_trigger_tx[op] = tx
                        self.outpoint_to_utxo.pop(op)

                    elif spent := self.outpoint_to_trigger_tx.get(op):
                        if find_vout_with_address(self.config.recov_address):
                            log.info("found recovery of triggered vault %s", spent)
                            log_history(RecoverEvent, spent)
                        else:
                            log_history(WithdrawalEvent, spent)

                # Detect deposits
                for vout in tx["vout"]:
                    if (addr := vout.get("scriptPubKey", {}).get("address")) and (
                        spec := self.addr_to_vault_spec.get(addr)
                    ):
                        op = Outpoint(tx["txid"], vout["n"])
                        self.outpoint_to_utxo[op] = (
                            utxo := VaultUtxo(
                                op,
                                addr,
                                btc_to_sats(vout["value"]),
                                height,
                                config=self.config,
                                vault_spec=spec,
                            )
                        )
                        log.info("found deposit to %s: %s", addr, utxo)
                        log_history(DepositEvent, utxo)

            self.last_height_scanned = height


@dataclass
class FeeWallet:
    """
    World's worst single-address wallet for fee management.
    """

    fee32: BIP32
    rpc: BitcoinRPC
    utxos: list[Utxo] = field(default_factory=list)

    def __post_init__(self):
        feepath = "m/0h/0"
        self.pubkey = self.fee32.get_pubkey_from_path(feepath)[1:]
        self.privkey = self.fee32.get_privkey_from_path(feepath)
        self.tr_info = script.taproot_construct(self.pubkey)
        self.fee_addr = core.address.output_key_to_p2tr(self.tr_info.output_pubkey)
        self.fee_spk = core.address.address_to_scriptpubkey(self.fee_addr)

    def rescan(self):
        self.utxos = []

        res = self.rpc.scantxoutset("start", [f"addr({self.fee_addr})"])
        if not (unspents := res.get("unspents")):
            log.warning("couldn't find any fee outputs")
            return

        for unspent in unspents:
            op = Outpoint(unspent["txid"], unspent["vout"])
            self.utxos.append(
                Utxo(
                    op,
                    self.fee_addr,
                    btc_to_sats(unspent["amount"]),
                    0,  # FIXME
                )
            )

    def sign_msg(self, msg: bytes) -> bytes:
        """Sign a message with the fee wallet's private key."""
        return core.key.sign_schnorr(
            core.key.tweak_add_privkey(self.privkey, self.tr_info.tweak), msg
        )

    def get_utxo(self) -> Utxo:
        self.rescan()
        try:
            return self.utxos.pop()
        except IndexError:
            raise RuntimeError(
                "Fee wallet empty! Add coins with "
                f"`bitcoin-cli -regtest generatetoaddress 20 {self.fee_addr}`"
            )


# Default sats to use for fees.
# TODO make this configurable, or smarter.
FEE_VALUE_SATS: int = 20_000


def get_recovery_tx(
    config: VaultConfig,
    fees: FeeWallet,
    utxos: list[VaultUtxo],
) -> CTransaction:
    total_sats = sum(u.value_sats for u in utxos)
    recov_spk = config.recov_taproot_info.scriptPubKey
    fee_utxo = fees.get_utxo()
    fee_change = fee_utxo.value_sats - FEE_VALUE_SATS
    assert fee_change > 0

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = [u.as_txin for u in utxos] + [fee_utxo.as_txin]
    tx.vout = [
        CTxOut(nValue=total_sats, scriptPubKey=recov_spk),
        CTxOut(nValue=fee_change, scriptPubKey=fees.fee_spk),
    ]
    recov_vout_idx = 0

    spent_outputs = [u.output for u in utxos] + [fee_utxo.output]

    # Authorize each input recovery with a schnorr signature.
    for i, utxo in enumerate(utxos):
        witness = core.messages.CTxInWitness()
        tx.wit.vtxinwit += [witness]

        tr_info: TaprootInfo = utxo.get_taproot_info()
        recover_script: CScript = tr_info.leaves["recover"].script

        sigmsg = script.TaprootSignatureHash(
            tx,
            spent_outputs,
            input_index=i,
            hash_type=0,
            scriptpath=True,
            script=recover_script,
        )

        witness.scriptWitness.stack = [
            script.bn2vch(recov_vout_idx),
            core.key.sign_schnorr(config.recovauth_privkey, sigmsg),
            recover_script,
            tr_info.controlblock_for_script_spend("recover"),
        ]

    # Sign for the fee input
    fee_witness = core.messages.CTxInWitness()
    tx.wit.vtxinwit += [fee_witness]

    sigmsg = script.TaprootSignatureHash(
        tx, spent_outputs, input_index=len(utxos), hash_type=0
    )

    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]

    return tx


@dataclass(frozen=True)
class PaymentDestination:
    addr: str
    value_sats: int

    def as_vout(self) -> CTxOut:
        return CTxOut(
            nValue=self.value_sats,
            scriptPubKey=core.address.address_to_scriptpubkey(self.addr),
        )


@dataclass
class WithdrawalBundle:
    """Necessary information to manage a vault withdrawal process."""

    trigger_spec: TriggerSpec
    trigger_tx: CTransaction
    withdrawal_tx: CTransaction


def _are_all_vaultspecs(lst: t.Any) -> t.TypeGuard[list[VaultSpec]]:
    return all(isinstance(s, VaultSpec) for s in lst)


def get_trigger_tx(
    config: VaultConfig,
    fees: FeeWallet,
    utxos: list[VaultUtxo],
    dest: PaymentDestination,
    trigger_privkey_For_vaultnum: t.Callable[[int], bytes],
) -> WithdrawalBundle:
    """
    Return transactions necessary to trigger a withdrawal to a single destination.

    Any remaining vault balance will be revaulted back into the vault.

    TODO generalize to multiple destinations
    TODO generalize to multiple incompatible vaults (i.e. many trigger outs)
    """
    fee_utxo = fees.get_utxo()
    fee_change = fee_utxo.value_sats - FEE_VALUE_SATS
    assert fee_change > 0

    # Choose the UTXO that we'll be revaulting from; this is the largest value, and
    # `utxos` should have been chosen so that the destination amount is covered by only
    # having one additional vault UTXO.
    revault_utxo = max(utxos, key=lambda u: u.value_sats)

    # Verify that coin selection was done properly.
    required_trigger_value = dest.value_sats + FEE_VALUE_SATS
    tmp_utxos = list(utxos)
    while required_trigger_value >= 0 and tmp_utxos:
        u = tmp_utxos.pop()
        required_trigger_value -= u.value_sats

    if required_trigger_value > 0 or len(tmp_utxos) not in [1, 0]:
        raise RuntimeError("coin selection is wrong! need at most one excess coin")

    needs_revault = required_trigger_value < 0
    total_vault_value = sum(u.value_sats for u in utxos)

    # Revault the remaining balance of the vault, less some fees that will be consumed
    # by the final withdrawal txn.
    #
    # This means that the input to the final withdrawal txn (ultimately provided by
    # the trigger output) will be slightly more than the destination payout.
    revault_value = total_vault_value - dest.value_sats - FEE_VALUE_SATS
    trigger_value = total_vault_value - revault_value
    assert revault_value > 0
    assert trigger_value > 0

    # Compute the final withdrawal transaction so that we may CTV hash it, and then
    # embed that hash in the trigger script. This is what "locks" the destination of
    # the withdrawal into place.

    final_tx = CTransaction()
    final_tx.nVersion = 2
    final_tx.vin = [CTxIn(nSequence=config.spend_delay)]
    final_tx.vout = [dest.as_vout()]
    ctv_hash = final_tx.get_standard_template_hash(0)

    specs = [u.vault_spec for u in utxos]
    assert _are_all_vaultspecs(specs)
    trigger_spec = TriggerSpec(specs, ctv_hash, trigger_value)

    trigger_out = CTxOut(nValue=trigger_value, scriptPubKey=trigger_spec.scriptPubKey)
    fee_change_out = CTxOut(nValue=fee_change, scriptPubKey=fees.fee_spk)
    revault_out = None
    revault_idx = None

    tx = CTransaction()
    tx.nVersion = 2
    tx.vin = [u.as_txin for u in utxos] + [fee_utxo.as_txin]
    tx.vout = [trigger_out, fee_change_out]
    trigger_vout_idx = 0

    if needs_revault:
        revault_out = CTxOut(
            nValue=revault_value, scriptPubKey=revault_utxo.scriptPubKey
        )
        tx.vout.append(revault_out)
        revault_idx = len(tx.vout) - 1

    spent_outputs = [u.output for u in utxos] + [fee_utxo.output]
    for i, utxo in enumerate(utxos):
        assert (spec := utxo.vault_spec)
        assert (trigger_script := spec.trigger_script)

        msg = script.TaprootSignatureHash(
            tx,
            spent_outputs,
            input_index=i,
            hash_type=0,
            scriptpath=True,
            script=trigger_script,
        )
        privkey: bytes = trigger_privkey_For_vaultnum(spec.vault_num)
        sig = core.key.sign_schnorr(privkey, msg)
        revault_value_script = script.bn2vch(0)
        revault_idx_script = script.bn2vch(-1)

        if needs_revault and utxo == revault_utxo:
            revault_value_script = script.bn2vch(revault_value)
            revault_idx_script = script.bn2vch(revault_idx)

        wit = core.messages.CTxInWitness()
        tx.wit.vtxinwit += [wit]
        wit.scriptWitness.stack = [
            revault_value_script,
            revault_idx_script,
            CScript([trigger_vout_idx]) if trigger_vout_idx != 0 else b"",
            ctv_hash,
            sig,
            trigger_script,
            utxo.get_taproot_info().controlblock_for_script_spend("trigger"),
        ]

    # Sign for the fee input
    fee_witness = core.messages.CTxInWitness()
    tx.wit.vtxinwit += [fee_witness]
    sigmsg = script.TaprootSignatureHash(
        tx, spent_outputs, input_index=len(utxos), hash_type=0
    )
    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]

    final_tx.vin[0].prevout = COutPoint(txid_to_int(tx.rehash()), trigger_vout_idx)
    final_tx.wit.vtxinwit += [core.messages.CTxInWitness()]
    final_tx.wit.vtxinwit[0].scriptWitness.stack = trigger_spec.withdrawal_witness
    assert final_tx.get_standard_template_hash(0) == ctv_hash

    return WithdrawalBundle(trigger_spec, tx, final_tx)


cli = App()


@dataclass
class WalletState:
    config: VaultConfig
    inflight_triggers: list[WithdrawalBundle]
    address_cursor: int

    filepath: Path | None = None

    _json_exclude = ('filepath',)

    def save(self):
        assert self.filepath
        self.filepath.write_text(Json.dumps(self, indent=2))
        log.info("saved wallet state to %s", self.filepath)

    @classmethod
    def load(cls, filepath: Path) -> "WalletState":
        obj = Json.loads(filepath.read_text())
        obj.filepath = filepath
        return obj


class Json:
    """
    Do a bunch of custom JSON serialization to save us writing a lot of boilerplate.
    """
    ALLOWED_CLASSES = {
        c.__name__: c for c in (
            WalletState, WithdrawalBundle, VaultConfig, VaultSpec, TriggerSpec,
        )
    }
    class Encoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return {'_type': 'hex', '_val': o.hex()}
            elif isinstance(o, CScript):
                return {'_type': 'CScript', '_val': o.hex()}
            elif isinstance(o, CTransaction):
                return {'_type': 'CTransaction', '_val': o.tohex()}

            elif (cls := Json.ALLOWED_CLASSES.get(o.__class__.__name__)):
                d = dict(o.__dict__)
                if (allowed_fields := getattr(o, '__dataclass_fields__', [])):
                    d = {k: v for k, v in o.__dict__.items() if k in allowed_fields}
                for ex in getattr(o, '_json_exclude', []):
                    d.pop(ex)
                d['__class__'] = cls.__name__
                return d

            return super().default(o)


    @classmethod
    def object_hook(cls, o: dict) -> object:
        if (ObjectClass := cls.ALLOWED_CLASSES.get(o.get('__class__', ''))):
            o.pop('__class__')
            return ObjectClass(**o)

        if (type_ := o.get('_type')) and (val := o.get('_val')) is not None:
            match type_:
                case "hex":
                    return bytes.fromhex(val)
                case 'CScript':
                    return CScript(bytes.fromhex(val))
                case 'CTransaction':
                    return CTransaction.fromhex(val)

        return o

    @classmethod
    def dumps(cls, *args, **kwargs):
        return json.dumps(*args, cls=cls.Encoder, **kwargs)

    @classmethod
    def loads(cls, *args, **kwargs):
        return json.loads(*args, object_hook=Json.object_hook, **kwargs)


def load(cfg_file: Path | str) -> tuple[WalletState, BitcoinRPC, FeeWallet]:
    fee32 = BIP32.from_seed(b"\x03")

    if not isinstance(cfg_file, Path):
        cfg_file = Path(cfg_file)
    if not cfg_file.exists():
        default_trigger_seed = b"\x02"
        default_recovery32 = BIP32.from_seed(b"\x01")
        default_recovery_pubkey = default_recovery32.get_pubkey_from_path("m/0h/0")
        default_recoveryauth_seed = b"\x04"

        config = VaultConfig(
            10, default_recovery_pubkey, default_trigger_seed, default_recoveryauth_seed
        )
        WalletState(config, [], 0, cfg_file).save()

    wallet_state = WalletState.load(cfg_file)
    rpc = BitcoinRPC(net_name=wallet_state.config.network)
    fees = FeeWallet(fee32, rpc)
    fees.rescan()

    return wallet_state, rpc, fees


@cli.main
def main():
    wallet_state, rpc, fees = load("./config.json")

    addrs = []
    for i in range(10):
        addrs.append(wallet_state.config.get_spec_for_vault_num(i).address)

    print(addrs)
    print(f"Fee address: {fees.fee_addr}")
    print()
    print(get_history(rpc, addrs))


@cli.cmd
def balance():
    wallet_state, rpc, fees = load("./config.json")
    monitor = ChainMonitor(wallet_state.config, rpc)
    monitor.rescan()
    print(f"Vault wallet (recovery: {wallet_state.config.recov_address})")
    for op, utxo in monitor.outpoint_to_utxo.items():
        print(f"  - {utxo.vault_spec.vault_num} ({utxo.value_sats}) @ {op.txid}:{op.n}")
    print()
    print("History")
    for hist in monitor.history:
        print(
            f"  - {hist.height}: {hist.__class__.__name__} for "
            f"{hist.utxos[0].address} ({hist.utxos[0].vault_spec.vault_num})"
        )

    print(f"Fee wallet ({fees.fee_addr})")
    for u in fees.utxos:
        print(f"  - {u.value_sats}: {u.outpoint_str}")


@cli.cmd
def recover(vault_outpoint: str):
    wallet_state, rpc, fees = load("./config.json")
    monitor = ChainMonitor(wallet_state.config, rpc)
    monitor.rescan()

    txid, n = vault_outpoint.split(":")
    op = Outpoint(txid, int(n))

    print(monitor.outpoint_to_utxo)
    if not (utxo := monitor.outpoint_to_utxo.get(op)):
        print("failed to find utxo!")
        sys.exit(1)

    tx = get_recovery_tx(wallet_state.config, fees, [utxo])
    tx.rehash()
    tx.pprint()

    rpc.sendrawtransaction(tx.tohex())


@cli.cmd
def withdraw(to_addr: str, amount_sats: int):
    wallet_state, rpc, fees = load("./config.json")
    monitor = ChainMonitor(wallet_state.config, rpc)
    monitor.rescan()
    dest = PaymentDestination(to_addr, amount_sats)

    # Use random coin selection to cover the amount.
    wallet_utxos = list(monitor.outpoint_to_utxo.values())
    utxos = []
    while amount_sats > 0:
        random.shuffle(wallet_utxos)
        utxos.append(utxo := wallet_utxos.pop())
        amount_sats -= utxo.value_sats

    def signer(vault_num):
        """Obviously don't use this in production; replace with something better."""
        return wallet_state.config.get_trigger_privkey(vault_num)

    bundle = get_trigger_tx(wallet_state.config, fees, utxos, dest, signer)
    wallet_state.inflight_triggers.append(bundle)
    wallet_state.save()
    rpc.sendrawtransaction(bundle.trigger_tx.tohex())

    print("waiting for trigger tx to confirm...")
    spec = bundle.trigger_spec
    trigger_txid = bundle.trigger_tx.rehash()

    confs = wallet.get_confs_for_txid(rpc, trigger_txid)
    while (confs or -1) < spec.spend_delay:
        new_confs = wallet.get_confs_for_txid(rpc, trigger_txid)

        if new_confs != confs:
            print(f"saw a new confirmation ({new_confs})")
            confs = new_confs
        time.sleep(2)

    print(f"trigger has matured! sending final withdrawal ({bundle.withdrawal_tx.rehash()})")
    rpc.sendrawtransaction(bundle.withdrawal_tx.tohex())


if __name__ == "__main__":
    cli.run()
