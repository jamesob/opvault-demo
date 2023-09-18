#!/usr/bin/env python3
import os
import sys
import random
import datetime
import signal
import json
import time
import typing as t
from collections import defaultdict
from functools import cached_property
from dataclasses import dataclass, field
from pathlib import Path

from clii import App
from bip32 import BIP32

import verystable
from verystable.script import CTransaction, TaprootInfo, cscript_bytes_to_int
from verystable import core, wallet
from verystable.rpc import BitcoinRPC, JSONRPCError
from verystable.core import script
from verystable.core.script import CScript
from verystable.core.messages import COutPoint, CTxOut, CTxIn

try:
    # If `rich` is installed, use pretty printing.
    from rich import print
except ImportError:
    pass

import logging

loglevel = "DEBUG" if os.environ.get("DEBUG") else "INFO"
log = logging.getLogger("opvault")
logging.basicConfig(filename="opvault-demo.log", level=loglevel)


verystable.softforks.activate_bip345_vault()
verystable.softforks.activate_bip119_ctv()


@dataclass
class VaultConfig:
    spend_delay: int
    recovery_pubkey: bytes
    trigger_seed: bytes
    recoveryauth_seed: bytes
    network: str = "regtest"

    # The blockheight that this wallet was created at.
    # Note: we won't scan for any activity beneath this height, so be careful when
    # specifying it.
    birthday_height: int = 0

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
        self.scriptPubKey = self.taproot_info.scriptPubKey
        self.address = core.address.output_key_to_p2tr(self.output_pubkey)

    @cached_property
    def recovery_address(self) -> str:
        # TODO: this assumes recovery is a p2tr - not always true!
        return core.address.output_key_to_p2tr(self.recovery_pubkey)


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
class TriggerSpec:
    """Manages script constructions and parameters for a triggered vault coin."""

    vault_specs: list[VaultSpec]
    destination_ctv_hash: bytes
    trigger_value_sats: int
    revault_value_sats: int
    destination: PaymentDestination
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    # The following are set after the trigger transaction is actually constructed.
    trigger_vout_idx: int = -1
    revault_vout_idx: int | None = None
    spent_vault_outpoints: list["Outpoint"] = field(default_factory=list)
    trigger_tx: CTransaction | None = None
    withdrawal_tx: CTransaction | None = None

    broadcast_trigger_at: datetime.datetime | None = None
    saw_trigger_confirmed_at: datetime.datetime | None = None
    saw_withdrawn_at: datetime.datetime | None = None

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

    @property
    def id(self) -> str:
        """Return a unique ID for this trigger spec."""
        assert self.trigger_tx
        return self.trigger_tx.rehash()

    @property
    def vault_num(self) -> int:
        return self.vault_specs[0].vault_num

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

    @cached_property
    def recovery_address(self) -> str:
        # TODO: this assumes recovery is a p2tr - not always true!
        return self.vault_specs[0].recovery_address


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
        assert bool(self.trigger_spec) ^ bool(self.vault_spec)

    @property
    def spec(self) -> VaultSpec | TriggerSpec:
        return self.trigger_spec or self.vault_spec

    def get_taproot_info(self):
        """Return the most relevant taproot info."""
        return self.spec.taproot_info

    def __str__(self) -> str:
        return f"{self.address} ({self.value_sats} sats) ({str(self.outpoint)})"

    def __hash__(self) -> int:
        return hash(self.outpoint)


@dataclass
class VaultsState:
    """
    A reflection of the current state of the vault.
    Tracks all assocated UTXOs within some gap limit.
    """

    blockhash: str
    height: int
    wallet_metadata: "WalletMetadata"
    addr_to_vault_spec: dict[str, VaultSpec]

    vault_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    trigger_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    theft_trigger_utxos: dict[VaultUtxo, CTransaction] = field(default_factory=dict)
    recovered_vaults: dict[str, VaultUtxo] = field(default_factory=dict)
    txid_to_completed_trigger: dict[str, VaultUtxo] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.vault_outpoint_to_good_trigger = {}
        self.txid_to_trigger_spec = {}

        for trig in self.wallet_metadata.triggers.values():
            assert trig.spent_vault_outpoints
            for outpoint in trig.spent_vault_outpoints:
                assert outpoint
                self.vault_outpoint_to_good_trigger[outpoint] = trig

            self.txid_to_trigger_spec[trig.id] = trig

    def update_for_tx(self, height: int, block: dict, tx: dict) -> None:
        txid = tx["txid"]
        trig_spec = self.txid_to_trigger_spec.get(txid)
        ctx = CTransaction.fromhex(tx["hex"])

        def get_spk(vout: dict) -> str | None:
            return vout.get("scriptPubKey", {}).get("address")

        # Detect deposits
        for vout in tx["vout"]:
            if addr := get_spk(vout):
                op = Outpoint(txid, vout["n"])

                if spec := self.addr_to_vault_spec.get(addr):
                    self.vault_utxos[op] = (
                        utxo := VaultUtxo(
                            op,
                            addr,
                            btc_to_sats(vout["value"]),
                            height,
                            config=self.wallet_metadata.config,
                            vault_spec=spec,
                        )
                    )
                    log.info("found deposit to %s: %s", addr, utxo)

                elif trig_spec and addr == trig_spec.address:
                    # Note: this does not cover *unknown* triggers, i.e. thefts. That
                    # is covered below.
                    trig_utxo = VaultUtxo(
                        op,
                        addr,
                        btc_to_sats(vout["value"]),
                        height,
                        config=self.wallet_metadata.config,
                        trigger_spec=trig_spec,
                    )
                    self.trigger_utxos[op] = trig_utxo
                    log.info("found trigger confirmation: %s", trig_utxo)

        def find_vout_with_address(findaddr: str) -> dict | None:
            for v in tx["vout"]:
                if findaddr == get_spk(v):
                    return v
            return None

        op_to_theft_trigger = {u.outpoint: u for u in self.theft_trigger_utxos.keys()}

        # Detect vault movements
        for vin in filter(lambda vin: "txid" in vin, tx["vin"]):
            spent_txid = vin["txid"]
            spent_op = Outpoint(spent_txid, vin.get("vout"))

            if spent := self.vault_utxos.get(spent_op):
                # Vault spent to recovery
                if find_vout_with_address(self.wallet_metadata.config.recov_address):
                    self.mark_vault_recovered(spent_op, txid)

                # Vault spent to trigger
                elif trigger := self.vault_outpoint_to_good_trigger.get(spent_op):
                    assert trigger.trigger_tx
                    if txid != trigger.trigger_tx.rehash():
                        log.warning(f"expected txn:\n{trigger.trigger_tx.pformat()}")
                        log.warning(f"got txn:\n{ctx.pformat()}")
                        self.mark_invalid_trigger_spend(spent, ctx)
                    else:
                        self.mark_vault_good_trigger(spent, trigger, height)

                # Vault spent to ??? -- theft!
                else:
                    self.mark_vault_bad_spend(spent, ctx)

            elif spent_trigger := self.trigger_utxos.get(spent_op):
                assert spent_trigger.trigger_spec
                assert (trigspec := spent_trigger.trigger_spec).withdrawal_tx

                # Trigger spent to recovery path
                if find_vout_with_address(trigspec.recovery_address):
                    self.mark_trigger_recovered(spent_trigger, txid)

                # Trigger spent to final withdrawal txn
                elif txid == trigspec.withdrawal_tx.rehash():
                    self.mark_trigger_completed(spent_trigger, txid)
                else:
                    log.warning("!!! unrecognized spend of trigger - shouldn't happen")

            elif (spent_theft_trigger := op_to_theft_trigger.get(spent_op)):
                if find_vout_with_address(spent_theft_trigger.spec.recovery_address):
                    # An attemped theft was thwarted successfully
                    log.warning("at risk trigger was succesfully recovered!")
                    self.recovered_vaults[txid] = spent_theft_trigger
                    self.theft_trigger_utxos.pop(spent_theft_trigger)
                else:
                    log.warning(
                        "at risk trigger was stolen, funds lost: game over, man ;(")

    def mark_vault_recovered(self, op: Outpoint, txid: str) -> None:
        spent = self.vault_utxos.pop(op)
        log.info("found recovery of untriggered vault %s", spent)
        self.recovered_vaults[txid] = spent

    def mark_invalid_trigger_spend(self, spent: VaultUtxo, tx: CTransaction) -> None:
        log.warning("found invalid trigger transaction for %s", spent)
        self.vault_utxos.pop(spent.outpoint)
        self.theft_trigger_utxos[get_recoverable_utxo_from_theft_tx(tx, spent)] = tx

    def mark_vault_good_trigger(
        self, spent: VaultUtxo, trigger: TriggerSpec, height: int
    ) -> None:
        log.info("found good trigger spend of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)

    def mark_vault_bad_spend(self, spent: VaultUtxo, tx: CTransaction) -> None:
        log.warning("found unrecognized spend of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)
        self.theft_trigger_utxos[get_recoverable_utxo_from_theft_tx(tx, spent)] = tx

    def mark_trigger_recovered(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found recovery of triggered vault %s", spent_trigger)
        self.trigger_utxos.pop(spent_trigger.outpoint)
        assert (spec := spent_trigger.trigger_spec)

        assert spec.spent_vault_outpoints
        for spent_vault_op in spec.spent_vault_outpoints:
            assert spent_vault_op
            self.recovered_vaults[txid] = self.vault_utxos.pop(spent_vault_op)

    def mark_trigger_completed(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found completed trigger %s", spent_trigger)
        self.txid_to_completed_trigger[txid] = self.trigger_utxos.pop(
            spent_trigger.outpoint
        )

    def get_next_deposit_num(self) -> int:
        """Get the next unused vault number."""

        def sum_vals(*dicts) -> list:
            out = []
            for d in dicts:
                out.extend(d.values())
            return out

        vaults = sum_vals(self.vault_utxos, self.recovered_vaults)
        trigs = sum_vals(self.trigger_utxos, self.txid_to_completed_trigger)
        nums = {u.spec.vault_num for u in vaults}
        nums.update({t.spec.vault_num for t in trigs})
        return 0 if not nums else max(nums) + 1


@dataclass
class ChainMonitor:
    wallet_metadata: "WalletMetadata"
    rpc: BitcoinRPC
    addr_to_vault_spec: dict[str, VaultSpec] = field(default_factory=dict)
    last_height_scanned: int = 0
    raw_history: list[tuple[int, dict]] = field(default_factory=list)
    latest_state: VaultsState | None = None

    def __post_init__(self):
        default_gap_limit = 200
        for i in range(default_gap_limit):
            spec = self.wallet_metadata.config.get_spec_for_vault_num(i)
            self.addr_to_vault_spec[spec.address] = spec

    def refresh_raw_history(self) -> None:
        MAX_REORG_DEPTH = 200
        start_height = max(0, self.last_height_scanned - MAX_REORG_DEPTH)

        # All vault + trigger output addresses, including attempted thefts.
        addrs: set[str] = set(self.addr_to_vault_spec.keys())
        addrs.update(self.wallet_metadata.all_trigger_addresses())

        if self.latest_state:
            # Pull in all vault UTXOs that we know of (as belt-and-suspenders).
            addrs.update({u.address for u in self.latest_state.vault_utxos.values()})
            addrs.update({
                u.address for u in self.latest_state.theft_trigger_utxos.keys()})

        # Evict history that we're going to refresh.
        new_history = [pair for pair in self.raw_history if pair[0] < start_height]
        new_history += wallet.get_relevant_blocks(self.rpc, addrs, start_height)
        self.raw_history = list(sorted(new_history))

    def rescan(self) -> VaultsState:
        self.refresh_raw_history()
        tip = self.rpc.getblock(self.rpc.getbestblockhash())
        s = VaultsState(
            tip["hash"], tip["height"], self.wallet_metadata, self.addr_to_vault_spec
        )

        # Replay blocks in ascending order, updating wallet state.
        for height, block in self.raw_history:
            for tx in block["tx"]:
                s.update_for_tx(height, block, tx)

            self.last_height_scanned = height

        self.latest_state = s
        return s


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


def _are_all_vaultspecs(lst: t.Any) -> t.TypeGuard[list[VaultSpec]]:
    return all(isinstance(s, VaultSpec) for s in lst)


def start_withdrawal(
    config: VaultConfig,
    fees: FeeWallet,
    utxos: list[VaultUtxo],
    dest: PaymentDestination,
    trigger_privkey_For_vaultnum: t.Callable[[int], bytes],
) -> TriggerSpec:
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
    trigger_spec = TriggerSpec(specs, ctv_hash, trigger_value, revault_value, dest)

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

    trigger_spec.trigger_vout_idx = trigger_vout_idx
    trigger_spec.revault_vout_idx = revault_idx
    trigger_spec.spent_vault_outpoints = [u.outpoint for u in utxos]

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

    trigger_spec.trigger_tx = tx
    trigger_spec.withdrawal_tx = final_tx
    return trigger_spec


cli = App()

TriggerId = str


@dataclass
class WalletMetadata:
    config: VaultConfig
    triggers: dict[TriggerId, TriggerSpec] = field(default_factory=dict)
    address_cursor: int = 0
    at_risk_trigger_utxos: list[VaultUtxo] = field(default_factory=dict)
    filepath: Path | None = None

    _json_exclude = ("filepath",)

    def save(self):
        assert self.filepath
        self.filepath.write_text(Json.dumps(self, indent=2))
        log.info("saved wallet state to %s", self.filepath)

    @classmethod
    def load(cls, filepath: Path) -> "WalletMetadata":
        obj = Json.loads(filepath.read_text())
        obj.filepath = filepath
        return obj

    def all_trigger_addresses(self) -> list[str]:
        """Get all trigger addresses, including attempted theft triggers."""
        return ([spec.address for spec in self.triggers.values()] +
            [u.address for u in self.at_risk_trigger_utxos])


class Json:
    """
    Do a bunch of custom JSON serialization to save us writing a lot of boilerplate.
    """

    ALLOWED_CLASSES = {
        c.__name__: c
        for c in (
            WalletMetadata,
            VaultConfig,
            VaultSpec,
            TriggerSpec,
            PaymentDestination,
            Outpoint,
        )
    }

    class Encoder(json.JSONEncoder):
        def default(self, o):
            if isinstance(o, bytes):
                return {"_type": "hex", "_val": o.hex()}
            elif isinstance(o, datetime.datetime):
                return {"_type": "datetime", "_val": o.isoformat()}
            elif isinstance(o, CScript):
                return {"_type": "CScript", "_val": o.hex()}
            elif isinstance(o, CTransaction):
                return {"_type": "CTransaction", "_val": o.tohex()}

            elif cls := Json.ALLOWED_CLASSES.get(o.__class__.__name__):
                d = dict(o.__dict__)
                if allowed_fields := getattr(o, "__dataclass_fields__", []):
                    d = {k: v for k, v in o.__dict__.items() if k in allowed_fields}
                for ex in getattr(o, "_json_exclude", []):
                    d.pop(ex)
                d["_class"] = cls.__name__
                return d

            return super().default(o)

    @classmethod
    def object_hook(cls, o: dict) -> object:
        if ObjectClass := cls.ALLOWED_CLASSES.get(o.get("_class", "")):
            o.pop("_class")
            return ObjectClass(**o)

        if (type_ := o.get("_type")) and (val := o.get("_val")) is not None:
            match type_:
                case "hex":
                    return bytes.fromhex(val)
                case "datetime":
                    return datetime.datetime.fromisoformat(val)
                case "CScript":
                    return CScript(bytes.fromhex(val))
                case "CTransaction":
                    return CTransaction.fromhex(val)

        return o

    @classmethod
    def dumps(cls, *args, **kwargs):
        return json.dumps(*args, cls=cls.Encoder, **kwargs)

    @classmethod
    def loads(cls, *args, **kwargs):
        return json.loads(*args, object_hook=Json.object_hook, **kwargs)


def load(
    cfg_file: Path | str,
) -> tuple[WalletMetadata, BitcoinRPC, FeeWallet, ChainMonitor, VaultsState]:
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
        WalletMetadata(config, filepath=cfg_file).save()

    wallet_metadata = WalletMetadata.load(cfg_file)
    rpc = BitcoinRPC(net_name=wallet_metadata.config.network)
    fees = FeeWallet(fee32, rpc)
    fees.rescan()

    monitor = ChainMonitor(wallet_metadata, rpc)
    state = monitor.rescan()
    wallet_metadata.address_cursor = state.get_next_deposit_num()

    return wallet_metadata, rpc, fees, monitor, state


def _sigint_handler(*args, **kwargs):
    sys.exit(0)


@cli.main
def main():
    """
    Vault watchtower functionality. Leave this running!
    """
    config_path = Path("./config.json")
    wallet_metadata, rpc, fees, monitor, state = load(config_path)
    next_spec = wallet_metadata.config.get_spec_for_vault_num(
        wallet_metadata.address_cursor
    )

    print(f"Next deposit address: {next_spec.address}")
    print()
    if state.vault_utxos:
        print("Vaulted coins")
        for u in state.vault_utxos.values():
            print(f"  - {u.address} ({u.value_sats} sats)")
            print(f"    outpoint: {str(u.outpoint)}")
        print()

    if state.trigger_utxos:
        print("Pending triggers")
        for trig in state.trigger_utxos.values():
            confs = state.height - trig.height
            print(f"  - {trig.spec.address} ({confs} confs) -> {trig.spec.destination}")
        print()

    if state.recovered_vaults:
        print("Recovered vaults")
        for u in state.recovered_vaults.values():
            print(f"  - {str(u)}")
        print()

    print(f"Fee wallet ({fees.fee_addr})")
    for u in fees.utxos[:2]:
        print(f"  - {u.value_sats}: {u.outpoint_str}")
    print()

    # Ensure any completed triggers have been marked completed.
    for trig_utxo in state.txid_to_completed_trigger.values():
        spec = wallet_metadata.triggers[trig_utxo.spec.id]
        now = datetime.datetime.utcnow()

        needs_save = False
        if not spec.saw_trigger_confirmed_at:
            spec.saw_trigger_confirmed_at = now
            needs_save = True
        if not spec.saw_withdrawn_at:
            spec.saw_withdrawn_at = now
            needs_save = True

        if needs_save:
            print(f"found that withdrawal {trig_utxo} has completed")
            # Save performed below

    wallet_metadata.save()
    trigger_txids_completed = set()

    signal.signal(signal.SIGINT, _sigint_handler)

    while True:
        new_state = monitor.rescan()
        # Reload wallet metadata file to pick up on new trigger jobs from `withdraw`.
        wallet_metadata = WalletMetadata.load(wallet_metadata.filepath)
        # TODO clean this up. If we don't set in lockstep with metadata refresh,
        # triggers will be unrecognized.
        monitor.wallet_metadata = wallet_metadata

        def new_values(key):
            newd = getattr(new_state, key)
            keydiff = set(newd.keys()) - set(getattr(state, key).keys())
            return {newd[k] for k in keydiff}

        # Submit trigger transactions for inflight withdrawals.
        for trig_spec in wallet_metadata.triggers.values():
            assert (tx := trig_spec.trigger_tx)

            if trig_spec.broadcast_trigger_at:
                # Trigger has already been broadcast.
                continue

            try:
                rpc.sendrawtransaction(tx.tohex())
            except JSONRPCError as e:
                # Already in blockchain.
                if e.code != -27:
                    raise
            else:
                print(
                    f"submitted trigger txn ({tx.rehash()}) "
                    f"for {trig_spec.destination}"
                )
                trig_spec.broadcast_trigger_at = datetime.datetime.utcnow()
                wallet_metadata.save()

        # Submit final withdrawal transactions for matured triggers.
        for trig_utxo in new_state.trigger_utxos.values():
            confs = new_state.height - trig_utxo.height
            left = (spec := trig_utxo.spec).spend_delay - confs
            is_mature = left <= 0
            finaltx = spec.withdrawal_tx
            txid = spec.trigger_tx.rehash()

            if not spec.saw_trigger_confirmed_at:
                wallet_metadata.triggers[
                    txid
                ].saw_trigger_confirmed_at = datetime.datetime.utcnow()
                wallet_metadata.save()

            if is_mature and txid not in trigger_txids_completed:
                print(f"trigger {trig_utxo} has matured ")
                print(f"broadcasting withdrawal txn ({finaltx.rehash()})")
                rpc.sendrawtransaction(finaltx.tohex())
                trigger_txids_completed.add(txid)
            elif new_state.height != state.height:
                print(f"trigger {spec.destination} has {confs} confs ({left}) to go")

        # Mark completed withdrawals as such.
        for trig_utxo in (has_new := new_values("txid_to_completed_trigger")):
            spec = trig_utxo.spec
            print(f"withdrawal to {spec.destination} completed")
            wallet_metadata.triggers[
                spec.id
            ].saw_withdrawn_at = datetime.datetime.utcnow()
            wallet_metadata.save()

        # Check for new vault deposits.
        for newv in (has_new := new_values("vault_utxos")):
            print(f"saw new deposit: {newv}")
            wallet_metadata.address_cursor += 1

        if has_new:
            wallet_metadata.save()
            next_spec = wallet_metadata.config.get_spec_for_vault_num(
                wallet_metadata.address_cursor
            )
            print(f"new deposit address: {next_spec.address}")

        # Alert on unrecognized spends.
        for theft_utxo, tx in state.theft_trigger_utxos.items():
            # TODO cooler alerting here
            print(f"!!! detected unrecognized spend (txid={tx.rehash()})!")
            print("    you might be hacked! run `recover` now!")

        if new_state.recovered_vaults and not new_state.vault_utxos:
            print("vault configuration fully recovered.")
            print("check your opsec, change your trigger key, and start over!")
            # FIXME recovered_vaults seems to be missing some coins here.
            for recovered in new_state.recovered_vaults.values():
                print(f"  - {recovered}")

            sys.exit(0)

        state = new_state
        time.sleep(2)


def get_recoverable_utxo_from_theft_tx(
    theft_trigger_tx: CTransaction, at_risk_utxo: VaultUtxo
) -> VaultUtxo:
    """
    Given an unrecognized trigger transaction (presumed to be a theft), create a
    VaultUtxo that can be used for recovery.
    """
    def num_decode(inp: bytes) -> int:
        return int.from_bytes(inp[::-1])

    coutp = at_risk_utxo.coutpoint
    [vin_num] = [
        i for i, vin in enumerate(theft_trigger_tx.vin)
        if vin.prevout.hash == coutp.hash and vin.prevout.n == coutp.n
    ]

    # Deconstruct the witness stack of the thief's trigger tx to recover parameters
    # (e.g. CTV hash) which we don't yet know, but will use to construct a recovery
    # script witness to spend this trigger with.

    wit = theft_trigger_tx.wit.vtxinwit[vin_num]
    stack = wit.scriptWitness.stack
    assert len(stack) == 7  # matches witstack format in start_withdrawal()
    revault_value_sats = cscript_bytes_to_int(stack[0])
    revault_idx = cscript_bytes_to_int(stack[1])
    trigger_vout_idx = cscript_bytes_to_int(stack[2])
    ctv_hash = stack[3]

    trigger_vout = theft_trigger_tx.vout[trigger_vout_idx]
    trigger_value_sats = trigger_vout.nValue

    assert at_risk_utxo.vault_spec

    adversary_spec = TriggerSpec(
        [at_risk_utxo.vault_spec],
        ctv_hash,
        trigger_value_sats,
        revault_value_sats,
        PaymentDestination("", 0),
        trigger_vout_idx=trigger_vout_idx,
        revault_vout_idx=revault_idx,
        trigger_tx=theft_trigger_tx,
    )
    assert adversary_spec.recover_wit_fragment

    return VaultUtxo(
        Outpoint(theft_trigger_tx.rehash(), trigger_vout_idx),
        address=adversary_spec.address,
        value_sats=trigger_value_sats,
        height=0,
        config=at_risk_utxo.config,
        trigger_spec=adversary_spec,
    )


@cli.cmd
def recover(outpoint: str = ""):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    utxos = (
        list(state.vault_utxos.values())
        + list(state.trigger_utxos.values())
        + list(state.theft_trigger_utxos.keys())
    )

    if outpoint:
        txid, n = outpoint.split(":")
        op = Outpoint(txid, int(n))
        utxos = [u for u in utxos if u.outpoint == op]
        if not utxos:
            print("failed to find utxo!")
            sys.exit(1)

    print("Recovering...")
    for u in utxos:
        print(f"  - {u}")

    tx = get_recovery_tx(wallet_metadata.config, fees, utxos)
    tx.rehash()

    rpc.sendrawtransaction(tx.tohex())


@cli.cmd
def withdraw(to_addr: str, amount_sats: int):
    internal_withdraw(to_addr, amount_sats)


@cli.cmd
def steal(to_addr: str, amount_sats: int):
    internal_withdraw(to_addr, amount_sats, simulate_theft=True)


def internal_withdraw(to_addr, amount_sats, simulate_theft: bool = False):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    dest = PaymentDestination(to_addr, amount_sats)

    # Use random coin selection to cover the amount.
    wallet_utxos = list(state.vault_utxos.values())
    utxos = []
    while amount_sats > 0:
        random.shuffle(wallet_utxos)
        utxos.append(utxo := wallet_utxos.pop())
        amount_sats -= utxo.value_sats

    def signer(vault_num):
        """Obviously don't use this in production; replace with something better."""
        return wallet_metadata.config.get_trigger_privkey(vault_num)

    spec = start_withdrawal(wallet_metadata.config, fees, utxos, dest, signer)
    assert spec.id not in wallet_metadata.triggers
    assert spec.trigger_tx

    if simulate_theft:
        rpc.sendrawtransaction(spec.trigger_tx.tohex())
        print("started theft, `monitor` should pick it up")
    else:
        wallet_metadata.triggers[spec.id] = spec
        wallet_metadata.save()
        print("started withdrawal process, `monitor` should pick it up")


if __name__ == "__main__":
    cli.run()
