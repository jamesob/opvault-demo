#!/usr/bin/env python3
import os
import sys
import random
import datetime
import signal
import json
import hashlib
import time
import typing as t
from functools import cached_property
from dataclasses import dataclass, field
from pathlib import Path, PosixPath

from clii import App
from bip32 import BIP32
import verystable
from verystable.script import CTransaction, TaprootInfo, cscript_bytes_to_int
from verystable import core, wallet
from verystable.rpc import BitcoinRPC, JSONRPCError
from verystable.core import script
from verystable.core.script import CScript
from verystable.core.messages import COutPoint, CTxOut, CTxIn
from verystable.wallet import SingleAddressWallet
from verystable.serialization import VSJson
from rich import print

import logging

loglevel = "DEBUG" if os.environ.get("DEBUG") else "INFO"
log = logging.getLogger("opvault")
logging.basicConfig(filename="opvault-demo.log", level=loglevel)

verystable.softforks.activate_bip345_vault()
verystable.softforks.activate_bip119_ctv()

# Override this if you're not running with docker-compose.
BITCOIN_RPC_URL = os.environ.get('BITCOIN_RPC_URL', 'http://bitcoin:18443')


@dataclass
class VaultConfig:
    """
    Static, non-secret configuration that describes the compatible parameters for a
    set of vault coins.
    """
    spend_delay: int
    recovery_pubkey: bytes
    recoveryauth_pubkey: bytes
    trigger_xpub: str
    network: str = "regtest"

    # Determines where trigger keys will be generated.
    trigger_xpub_path_prefix: str = "m/0"

    # The blockheight that this wallet was created at.
    # Note: we won't scan for any activity beneath this height, so be careful when
    # specifying it.
    birthday_height: int = 0

    secrets_filepath: Path = Path('./secrets.json')

    def __post_init__(self) -> None:
        assert len(self.recovery_pubkey) == 32
        assert len(self.recoveryauth_pubkey) == 32
        self.trigger_xpub_path_prefix = self.trigger_xpub_path_prefix.rstrip('/')

    @property
    def id(self) -> str:
        """A string that uniquely IDs this vault configuration."""
        return (
            f"{self.network}-{self.spend_delay}-{self.recovery_pubkey.hex()}-"
            f"{self.recoveryauth_pubkey.hex()}-{self.trigger_xpub}")

    @cached_property
    def recov_taproot_info(self) -> TaprootInfo:
        return script.taproot_construct(self.recovery_pubkey)

    @cached_property
    def recov_address(self) -> str:
        return core.address.output_key_to_p2tr(self.recov_taproot_info.output_pubkey)

    def get_trigger_xonly_pubkey(self, num: int) -> bytes:
        b32 = BIP32.from_xpub(self.trigger_xpub)
        got = b32.get_pubkey_from_path(f"{self.trigger_xpub_path_prefix}/{num}")
        assert len(got) == 33
        return got[1:]

    def get_spec_for_vault_num(self, num: int) -> "VaultSpec":
        return VaultSpec(
            vault_num=num,
            spend_delay=self.spend_delay,
            trigger_pubkey=self.get_trigger_xonly_pubkey(num),
            recovery_pubkey=self.recov_taproot_info.output_pubkey,
            recovery_spk=self.recov_taproot_info.scriptPubKey,
            recoveryauth_pubkey=self.recoveryauth_pubkey,
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
    recoveryauth_pubkey: bytes

    # Determines the behavior of the withdrawal process.
    leaf_update_script_body = (
        script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP, script.OP_CHECKTEMPLATEVERIFY,
    )  # yapf: disable

    def __post_init__(self):
        assert len(self.trigger_pubkey) == 32
        assert len(self.recovery_pubkey) == 32
        assert len(self.recoveryauth_pubkey) == 32

        recov_hash = core.key.TaggedHash(
            "VaultRecoverySPK", core.messages.ser_string(self.recovery_spk))

        self.recovery_script = CScript([
            self.recoveryauth_pubkey, script.OP_CHECKSIGVERIFY, recov_hash,
            script.OP_VAULT_RECOVER,
        ])  # yapf: disable

        self.trigger_script = CScript([
            self.trigger_pubkey, script.OP_CHECKSIGVERIFY, self.spend_delay,
            2, CScript(self.leaf_update_script_body), script.OP_VAULT,
        ])  # yapf: disable

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


def recoveryauth_phrase_to_key(phrase: str) -> core.key.ECKey:
    """
    The intent of the recovery authorization key is to prevent passive attackers from
    fee-griefing recovery transactions, so it doesn't need to be as secure as most keys.

    Use key derivation to generate a privkey based on a memorable phrase that can be
    trivially written down offline and used in case of need for recovery.
    """
    seed = hashlib.pbkdf2_hmac(
        "sha256", phrase.encode(), salt=b"OP_VAULT", iterations=3_000_000)
    (key := core.key.ECKey()).set(seed, compressed=True)
    return key


@dataclass(frozen=True)
class PaymentDestination:
    addr: str
    value_sats: int

    def as_vout(self) -> CTxOut:
        return CTxOut(
            nValue=self.value_sats,
            scriptPubKey=core.address.address_to_scriptpubkey(self.addr),
        )


@dataclass(frozen=True)
class Outpoint:
    txid: str
    n: int

    def __str__(self) -> str:
        return f"{self.txid}:{self.n}"

    def __hash__(self) -> int:
        return hash(str(self))

    def __eq__(self, o) -> bool:
        return self.__dict__ == o.__dict__


@dataclass
class TriggerSpec:
    """Manages script constructions and parameters for a triggered vault coin."""

    vault_specs: list[VaultSpec]
    destination_ctv_hash: bytes
    trigger_value_sats: int
    revault_value_sats: int
    created_at: datetime.datetime = field(default_factory=datetime.datetime.utcnow)

    # The following are set after the trigger transaction is actually constructed.
    trigger_vout_idx: int = -1
    revault_vout_idx: int | None = None
    spent_vault_outpoints: list[Outpoint] = field(default_factory=list)
    spent_fee_outpoints: list[Outpoint] = field(default_factory=list)
    trigger_tx: CTransaction | None = None
    withdrawal_tx: CTransaction | None = None
    # Used only for logging.
    destination: PaymentDestination | None = None

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

        self.withdrawal_script = CScript([
            self.destination_ctv_hash,
            vault_spec.spend_delay,
            *vault_spec.leaf_update_script_body,
        ])
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
    def recovery_address(self) -> str:
        return self.vault_specs[0].recovery_address


def txid_to_int(txid: str) -> int:
    return int.from_bytes(bytes.fromhex(txid), byteorder="big")


def btc_to_sats(btc) -> int:
    return int(btc * core.messages.COIN)


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

    def __hash__(self) -> int:
        return hash(str(self.outpoint))


@dataclass(frozen=True)
class VaultUtxo(Utxo):
    config: VaultConfig

    vault_spec: VaultSpec | None = None
    trigger_spec: TriggerSpec | None = None

    def __post_init__(self):
        assert bool(self.trigger_spec) ^ bool(self.vault_spec)

    @property
    def spec(self) -> VaultSpec | TriggerSpec:
        assert (s := self.trigger_spec or self.vault_spec)
        return s

    def get_taproot_info(self):
        """Return the most relevant taproot info."""
        return self.spec.taproot_info

    def __str__(self) -> str:
        return (f"{str(self.outpoint)} ({self.value_sats} sats)\n    (addr={self.address})")

    def __hash__(self) -> int:
        return hash(self.outpoint)


@dataclass
class VaultsState:
    """
    A snapshot of the current state of the vault at a particular block (tip).

    A "pure" class in the sense tha it doesn't make RPC calls or manipulate
    any state outside of what is maintained in this class - it just interpets
    a history of blocks to build a snapshot of the vault.
    """

    blockhash: str
    height: int
    vault_config: VaultConfig
    authorized_triggers: list[TriggerSpec]
    addr_to_vault_spec: dict[str, VaultSpec]

    vault_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    trigger_utxos: dict[Outpoint, VaultUtxo] = field(default_factory=dict)
    theft_trigger_utxos: dict[VaultUtxo, CTransaction] = field(default_factory=dict)
    recovered_vaults: dict[VaultUtxo, str] = field(default_factory=dict)
    txid_to_completed_trigger: dict[str, VaultUtxo] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.vault_outpoint_to_good_trigger = {}
        self.txid_to_trigger_spec = {}

        for trig in self.authorized_triggers:
            assert trig.spent_vault_outpoints
            for outpoint in trig.spent_vault_outpoints:
                assert outpoint
                self.vault_outpoint_to_good_trigger[outpoint] = trig

            self.txid_to_trigger_spec[trig.id] = trig

        log.info(
            "vault outpoints to good triggers: %s", {
                k: v.id for k, v in self.vault_outpoint_to_good_trigger.items()})

    def update_for_tx(self, height: int, block: dict, tx: dict) -> None:
        txid = tx["txid"]
        trig_spec = self.txid_to_trigger_spec.get(txid)
        ctx = CTransaction.fromhex(tx["hex"])

        def get_spk(vout: dict) -> str | None:
            return vout.get("scriptPubKey", {}).get("address")

        # Examine outputs
        for vout in tx["vout"]:
            if addr := get_spk(vout):
                op = Outpoint(txid, vout["n"])

                # Detect deposits
                if spec := self.addr_to_vault_spec.get(addr):
                    self.vault_utxos[op] = (
                        utxo := VaultUtxo(
                            op,
                            addr,
                            btc_to_sats(vout["value"]),
                            height,
                            config=self.vault_config,
                            vault_spec=spec,
                        ))
                    log.info("found deposit to %s: %s", addr, utxo)

                elif trig_spec and addr == trig_spec.address:
                    # Note: this does not cover *unknown* triggers, i.e. thefts. That
                    # is covered below.
                    trig_utxo = VaultUtxo(
                        op,
                        addr,
                        btc_to_sats(vout["value"]),
                        height,
                        config=self.vault_config,
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
                if find_vout_with_address(self.vault_config.recov_address):
                    self.mark_vault_recovered(spent_op, txid)

                # Vault spent to trigger
                elif trigger := self.vault_outpoint_to_good_trigger.get(spent_op):
                    assert trigger.trigger_tx
                    if txid != trigger.trigger_tx.rehash():
                        log.warning(
                            "got bad trigger! expected\n%s",
                            trigger.trigger_tx.pformat())
                        log.warning("got bad trigger! got\n%s", ctx.pformat())
                        self.mark_vault_theft(spent, ctx)
                    else:
                        self.mark_vault_good_trigger(spent, trigger, height)

                # Vault spent to ??? -- theft!
                else:
                    self.mark_vault_theft(spent, ctx)

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

            elif spent_theft_trigger := op_to_theft_trigger.get(spent_op):
                if find_vout_with_address(spent_theft_trigger.spec.recovery_address):
                    # An attemped theft was thwarted successfully
                    log.warning("at risk trigger was succesfully recovered!")
                    self.recovered_vaults[spent_theft_trigger] = txid
                    self.theft_trigger_utxos.pop(spent_theft_trigger)
                else:
                    log.warning(
                        "at risk trigger was stolen, funds lost: game over, man ;(")

    def mark_vault_recovered(self, op: Outpoint, txid: str) -> None:
        spent = self.vault_utxos.pop(op)
        log.info("found recovery of untriggered vault %s", spent)
        self.recovered_vaults[spent] = txid

    def mark_vault_good_trigger(
            self, spent: VaultUtxo, trigger: TriggerSpec, height: int) -> None:
        log.info("found good trigger spend of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)

    def mark_vault_theft(self, spent: VaultUtxo, tx: CTransaction) -> None:
        log.warning("found unrecognized spend (attempted theft?) of vault %s", spent)
        self.vault_utxos.pop(spent.outpoint)
        self.theft_trigger_utxos[get_recoverable_utxo_from_theft_tx(tx, spent)] = tx

    def mark_trigger_recovered(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found recovery of triggered vault %s", spent_trigger)
        self.trigger_utxos.pop(spent_trigger.outpoint)
        assert (spec := spent_trigger.trigger_spec)

        assert spec.spent_vault_outpoints
        for spent_vault_op in spec.spent_vault_outpoints:
            assert spent_vault_op
            spent = self.vault_utxos.pop(spent_vault_op)
            self.recovered_vaults[spent] = txid

    def mark_trigger_completed(self, spent_trigger: VaultUtxo, txid: str) -> None:
        log.info("found completed trigger %s", spent_trigger)
        self.txid_to_completed_trigger[txid] = self.trigger_utxos.pop(
            spent_trigger.outpoint)

    def get_next_deposit_num(self) -> int:
        """Get the next unused vault number."""
        utxos = [
            *self.vault_utxos.values(),
            *self.recovered_vaults.keys(),
            *self.trigger_utxos.values(),
            *self.txid_to_completed_trigger.values(),
        ]
        nums = {u.spec.vault_num for u in utxos}
        return 0 if not nums else max(nums) + 1


@dataclass
class ChainMonitor:
    """
    Fetches data from a bitcoin RPC to build the state of the vault.
    """
    wallet_metadata: "WalletMetadata"
    rpc: BitcoinRPC
    addr_to_vault_spec: dict[str, VaultSpec] = field(default_factory=dict)
    last_height_scanned: int = 0
    raw_history: list[tuple[int, dict]] = field(default_factory=list)
    latest_state: VaultsState | None = None

    def __post_init__(self):
        DEFAULT_GAP_LIMIT = 200
        for i in range(DEFAULT_GAP_LIMIT):
            spec = self.wallet_metadata.config.get_spec_for_vault_num(i)
            self.addr_to_vault_spec[spec.address] = spec

    def refresh_raw_history(self) -> None:
        MAX_REORG_DEPTH = 200
        start_height = max(
            0,
            max(
                self.wallet_metadata.config.birthday_height,
                self.last_height_scanned,
            ) - MAX_REORG_DEPTH)

        # All vault + trigger output addresses, including attempted thefts.
        addrs: set[str] = set(self.addr_to_vault_spec.keys())
        addrs.update(self.wallet_metadata.all_trigger_addresses())

        # TODO theoretically could miss early theft-trigger-recovers here if this is
        # None.
        if self.latest_state:
            # Pull in all vault UTXOs that we know of (as belt-and-suspenders).
            addrs.update({u.address for u in self.latest_state.vault_utxos.values()})
            addrs.update(
                {u.address for u in self.latest_state.theft_trigger_utxos.keys()})

        # Evict history that we're going to refresh.
        new_history = [pair for pair in self.raw_history if pair[0] < start_height]
        new_history += wallet.get_relevant_blocks(self.rpc, addrs, start_height)
        self.raw_history = list(sorted(new_history))

    def rescan(self) -> VaultsState:
        self.refresh_raw_history()
        tip = self.rpc.getblock(self.rpc.getbestblockhash())
        s = VaultsState(
            tip["hash"],
            tip["height"],
            vault_config=self.wallet_metadata.config,
            authorized_triggers=list(self.wallet_metadata.triggers.values()),
            addr_to_vault_spec=self.addr_to_vault_spec,
        )

        # Replay blocks in ascending order, updating wallet state.
        for height, block in self.raw_history:
            for tx in block["tx"]:
                s.update_for_tx(height, block, tx)

            self.last_height_scanned = height

        self.latest_state = s
        return s


# Default sats to use for fees.
# TODO make this configurable, or smarter.
FEE_VALUE_SATS: int = 20_000


@dataclass
class RecoverySpec:
    tx: CTransaction
    spent_vault_outpoints: list[Outpoint] = field(default_factory=list)
    spent_fee_outpoints: list[Outpoint] = field(default_factory=list)


def get_recovery_tx(
    config: VaultConfig,
    fees: SingleAddressWallet,
    utxos: list[VaultUtxo],
    recoveryauth_signer: t.Callable[[bytes], bytes],
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
            recoveryauth_signer(sigmsg),
            recover_script,
            tr_info.controlblock_for_script_spend("recover"),
        ]

    # Sign for the fee input
    fee_witness = core.messages.CTxInWitness()
    tx.wit.vtxinwit += [fee_witness]

    sigmsg = script.TaprootSignatureHash(
        tx, spent_outputs, input_index=len(utxos), hash_type=0)

    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]
    return RecoverySpec(
        tx,
        spent_vault_outpoints=[u.outpoint for u in utxos],
        spent_fee_outpoints=[fee_utxo.outpoint])


def _are_all_vaultspecs(lst: t.Any) -> t.TypeGuard[list[VaultSpec]]:
    return all(isinstance(s, VaultSpec) for s in lst)


def start_withdrawal(
    config: VaultConfig,
    fees: wallet.SingleAddressWallet,
    utxos: list[VaultUtxo],
    dest: PaymentDestination,
    trigger_xpriv_signer: t.Callable[[bytes, int], bytes],
) -> TriggerSpec:
    """
    Return TriggerSpec necessary to trigger a withdrawal to a single destination.

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
    trigger_spec = TriggerSpec(
        specs,
        ctv_hash,
        trigger_value,
        revault_value,
        spent_vault_outpoints=[u.outpoint for u in utxos],
        spent_fee_outpoints=[fee_utxo.outpoint],
        destination=dest)

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
            nValue=revault_value, scriptPubKey=revault_utxo.scriptPubKey)
        tx.vout.append(revault_out)
        revault_idx = len(tx.vout) - 1

    trigger_spec.trigger_vout_idx = trigger_vout_idx
    trigger_spec.revault_vout_idx = revault_idx

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
        sig: bytes = trigger_xpriv_signer(msg, spec.vault_num)
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
        tx, spent_outputs, input_index=len(utxos), hash_type=0)
    fee_witness.scriptWitness.stack = [fees.sign_msg(sigmsg)]

    final_tx.vin[0].prevout = COutPoint(txid_to_int(tx.rehash()), trigger_vout_idx)
    final_tx.wit.vtxinwit += [core.messages.CTxInWitness()]
    final_tx.wit.vtxinwit[0].scriptWitness.stack = [
        trigger_spec.taproot_info.leaves["withdraw"].script,
        trigger_spec.taproot_info.controlblock_for_script_spend("withdraw"),
    ]
    assert final_tx.get_standard_template_hash(0) == ctv_hash

    trigger_spec.trigger_tx = tx
    trigger_spec.withdrawal_tx = final_tx
    return trigger_spec


def get_recoverable_utxo_from_theft_tx(
        theft_trigger_tx: CTransaction, at_risk_utxo: VaultUtxo) -> VaultUtxo:
    """
    Given an unrecognized trigger transaction (presumed to be a theft), create a
    VaultUtxo that can be used to spend it to the recovery path.
    """
    coutp = at_risk_utxo.coutpoint
    [vin_num] = [
        i for i,
        vin in enumerate(theft_trigger_tx.vin)
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
        trigger_vout_idx=trigger_vout_idx,
        revault_vout_idx=revault_idx,
        trigger_tx=theft_trigger_tx,
    )

    return VaultUtxo(
        Outpoint(theft_trigger_tx.rehash(), trigger_vout_idx),
        address=adversary_spec.address,
        value_sats=trigger_value_sats,
        height=0,
        config=at_risk_utxo.config,
        trigger_spec=adversary_spec,
    )


cli = App()

TriggerId = str


@dataclass
class WalletMetadata:
    config: VaultConfig
    triggers: dict[TriggerId, TriggerSpec] = field(default_factory=dict)
    recoveries: list[RecoverySpec] = field(default_factory=list)
    address_cursor: int = 0
    filepath: Path | None = None

    # In practice, you wouldn't persist this here but for the purposes of a demo
    # it's fine.
    fee_wallet_seed: bytes = b'\x01' * 32

    _json_exclude = ("filepath",)

    def save(self):
        assert self.filepath
        self.filepath.write_text(VSJson.dumps(self, indent=2))
        log.info("saved wallet state to %s", self.filepath)

    @classmethod
    def load(cls, filepath: Path) -> "WalletMetadata":
        obj = VSJson.loads(filepath.read_text())
        obj.filepath = filepath
        return obj

    def all_trigger_addresses(self) -> list[str]:
        """Get all trigger addresses, including attempted theft triggers."""
        return [spec.address for spec in self.triggers.values()]

    def get_vault_utxos_spent_by_triggers(self) -> set[Outpoint]:
        return {
            op for trig in self.triggers.values() for op in trig.spent_vault_outpoints
        }

    def get_locked_fee_outpoints(self) -> set[Outpoint]:
        specs: list[TriggerSpec | RecoverySpec] = (
            self.recoveries + list(self.triggers.values()))
        return {op for spec in specs for op in spec.spent_fee_outpoints}


# Wire up JSON serialization for the classes above.
VSJson.add_allowed_classes(
    Outpoint,
    WalletMetadata,
    VaultConfig,
    VaultSpec,
    TriggerSpec,
    PaymentDestination,
    Path,
    PosixPath,
)


def load(
    cfg_file: Path | str,
) -> tuple[WalletMetadata, BitcoinRPC, SingleAddressWallet, ChainMonitor, VaultsState]:
    """
    Load configuration from the fileystem and initialize wallet state.
    """
    if not isinstance(cfg_file, Path):
        cfg_file = Path(cfg_file)
    if not cfg_file.exists():
        print("call ./createconfig.py")
        sys.exit(1)

    wallet_metadata = WalletMetadata.load(cfg_file)
    rpc = BitcoinRPC(
        net_name=wallet_metadata.config.network, service_url=BITCOIN_RPC_URL)
    fees = SingleAddressWallet(
        rpc,
        locked_utxos=[wallet_metadata.get_locked_fee_outpoints()],
        seed=wallet_metadata.fee_wallet_seed,
    )
    fees.rescan()

    monitor = ChainMonitor(wallet_metadata, rpc)
    state = monitor.rescan()
    wallet_metadata.address_cursor = state.get_next_deposit_num()

    return wallet_metadata, rpc, fees, monitor, state


def _sigint_handler(*args, **kwargs):
    sys.exit(0)


@cli.main
@cli.cmd
def monitor():
    """
    Vault watchtower functionality. Leave this running!
    """
    config_path = Path("./config.json")
    wallet_metadata, rpc, fees, monitor, state = load(config_path)
    next_spec = wallet_metadata.config.get_spec_for_vault_num(
        wallet_metadata.address_cursor)

    print(
        """


                 w e l c o m e
                                t o
                      y o u r
                                      ▀██    ▄
            ▄▄▄▄ ▄▄▄  ▄▄▄▄   ▄▄▄ ▄▄▄   ██  ▄██▄
             ▀█▄  █  ▀▀ ▄██   ██  ██   ██   ██
              ▀█▄█   ▄█▀ ██   ██  ██   ██   ██
               ▀█    ▀█▄▄▀█▀  ▀█▄▄▀█▄ ▄██▄  ▀█▄▀


""")

    def print_activity(*lines) -> None:
        oth = "\n     ".join(str(i) for i in lines[1:])
        print(f" {lines[0]}\n    {oth}\n")

    print_activity(f"[cyan bold]=>[/] next deposit address", next_spec.address)
    if state.vault_utxos:
        print(" [bold]Vaulted coins[/]\n")
        for u in state.vault_utxos.values():
            print(f"  - {u.address} ({u.value_sats} sats)")
            print(f"    outpoint: {str(u.outpoint)}")
        print()

    if state.trigger_utxos:
        print(" [bold]Pending triggers[/]\n")
        for trig in state.trigger_utxos.values():
            confs = state.height - trig.height
            print(f"  - {trig.spec.address} ({confs} confs) -> {trig.spec.destination}")
        print()

    if state.recovered_vaults:
        print("[bold]Recovered vaults[/]\n")
        for u in state.recovered_vaults:
            print(f"  - {str(u)}")
        print()

    print(f"[green bold] $$[/] fee wallet address: {fees.fee_addr}")
    for u in fees.utxos[:3]:
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
            print_activity(
                f"[bold]✔ [/] found that withdrawal has completed", trig_utxo)
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
                print_activity(
                    f"[bold]❏ [/] submitted trigger txn for",
                    trig_spec.destination,
                    f"(txid={tx.rehash()})")
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
                    txid].saw_trigger_confirmed_at = datetime.datetime.utcnow()
                wallet_metadata.save()

            if is_mature and txid not in trigger_txids_completed:
                print_activity(f"[yellow]✅[/] trigger has matured", trig_utxo)
                print_activity(
                    f"[bold]<-[/] broadcasting withdrawal txn", finaltx.rehash())
                rpc.sendrawtransaction(finaltx.tohex())
                trigger_txids_completed.add(txid)
            elif new_state.height != state.height:
                print_activity(
                    f"[bold]--[/] trigger has {confs} confs ({left} to go)",
                    f"(txid={txid})",
                    spec.destination,
                )

        # Mark completed withdrawals as such.
        for trig_utxo in (has_new := new_values("txid_to_completed_trigger")):
            spec = trig_utxo.spec
            print_activity(f"[blue]✅[/] withdrawal completed", spec.destination)
            wallet_metadata.triggers[
                spec.id].saw_withdrawn_at = datetime.datetime.utcnow()
            wallet_metadata.save()

        # Check for new vault deposits.
        for newv in (has_new := new_values("vault_utxos")):
            print_activity(f"[green]$$[/] saw new deposit", newv)
            wallet_metadata.address_cursor += 1

        if has_new:
            wallet_metadata.save()
            next_spec = wallet_metadata.config.get_spec_for_vault_num(
                wallet_metadata.address_cursor)
            print_activity(f"[bold]▢ [/] new deposit address", next_spec.address)

        # Alert on unrecognized spends.
        for theft_utxo, tx in state.theft_trigger_utxos.items():
            # TODO cooler alerting here
            print_activity(
                f" [red bold]!![/] detected unrecognized spend!",
                "  you might be hacked! run `recover` now!",
                f"(bad txid={tx.rehash()})")

        if new_state.recovered_vaults and not new_state.vault_utxos:
            print()
            print_activity(
                "[cyan bold]✔✔[/] vault configuration fully recovered",
                f"recovered to: [blue]{wallet_metadata.config.recov_address}[/]",
                "",
                "check your opsec, change your trigger key, and start over!"
            )
            print(" vaults recovered:")
            for recovered in new_state.recovered_vaults:
                print(f"  - {recovered}")
            print()

            sys.exit(0)

        state = new_state
        time.sleep(2)


@cli.cmd
def withdraw(to_addr: str, amount_sats: int):
    """Trigger the start of a withdrawal process from the vault."""
    _cli_start_withdrawal(to_addr, amount_sats)


@cli.cmd
def steal(to_addr: str, amount_sats: int):
    """Simulate a theft out of the vault."""
    _cli_start_withdrawal(to_addr, amount_sats, simulate_theft=True)


def _cli_start_withdrawal(to_addr, amount_sats, simulate_theft: bool = False):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    config = wallet_metadata.config
    dest = PaymentDestination(to_addr, amount_sats)

    # Use random coin selection to cover the amount.
    wallet_utxos = list(state.vault_utxos.values())

    if not simulate_theft:
        already_locked = wallet_metadata.get_vault_utxos_spent_by_triggers()
        # If we aren't thieving, exclude UTXOs that are already locked by other
        # pending triggers.
        wallet_utxos = [u for u in wallet_utxos if u.outpoint not in already_locked]

    utxos = []
    while amount_sats > 0:
        random.shuffle(wallet_utxos)
        utxos.append(utxo := wallet_utxos.pop())
        amount_sats -= utxo.value_sats

    def trigger_key_signer(msg: bytes, vault_num: int) -> bytes:
        """Obviously don't use this in production; replace with something better."""
        try:
            secdict = json.loads(config.secrets_filepath.read_text())[config.id]
            b32 = BIP32.from_xpriv(secdict['trigger_xpriv'])
        except Exception:
            log.exception("unable to find secrets for vault config %s", config.id)
            sys.exit(1)

        privkey = b32.get_privkey_from_path(
            f"{config.trigger_xpub_path_prefix}/{vault_num}")
        sig = core.key.sign_schnorr(privkey, msg)
        return sig

    spec = start_withdrawal(
        wallet_metadata.config, fees, utxos, dest, trigger_key_signer)
    assert spec.id not in wallet_metadata.triggers
    assert spec.trigger_tx

    if not simulate_theft:
        # Add the trigger spec as recognized and queue it for processing
        # by the watchtower.
        wallet_metadata.triggers[spec.id] = spec
        wallet_metadata.save()
        print("started withdrawal process, `monitor` should pick it up")
    else:
        rpc.sendrawtransaction(spec.trigger_tx.tohex())
        print("started theft, `monitor` should detect it after block is mined")


@cli.cmd
def recover(outpoint: str = ""):
    wallet_metadata, rpc, fees, monitor, state = load("./config.json")
    utxos = [
        *state.vault_utxos.values(),
        *state.trigger_utxos.values(),
        *state.theft_trigger_utxos.keys(),
    ]

    if outpoint:
        txid, n = outpoint.split(":")
        op = Outpoint(txid, int(n))
        utxos = [u for u in utxos if u.outpoint == op]
        if not utxos:
            print("failed to find utxo!")
            sys.exit(1)

    print("\nRecovering...")
    for u in utxos:
        print(f"  - {u}")

    print()
    phrase = input('Enter recovery phrase (check `secrets.json`): ')
    recovery_privkey = recoveryauth_phrase_to_key(phrase).get_bytes()

    def recoveryauth_signer(msg: bytes) -> bytes:
        """Prompt the user for the recovery phrase."""
        return core.key.sign_schnorr(recovery_privkey, msg)

    spec = get_recovery_tx(wallet_metadata.config, fees, utxos, recoveryauth_signer)
    wallet_metadata.recoveries.append(spec)

    rpc.sendrawtransaction(spec.tx.tohex())
    print(f"recovery txn ({spec.tx.rehash()}) now in mempool - mine some blocks")


if __name__ == "__main__":
    cli.run()
