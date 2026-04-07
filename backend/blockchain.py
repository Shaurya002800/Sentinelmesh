from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from web3 import Web3

from config import CONTRACT_ADDRESS, PRIVATE_KEY, RPC_URL

CONTRACT_ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "hash", "type": "bytes32"}],
        "name": "storeIncident",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


class BlockchainAnchor:
    def __init__(self) -> None:
        self.enabled = bool(RPC_URL and PRIVATE_KEY and CONTRACT_ADDRESS)
        self.web3 = None
        self.account = None
        self.contract = None

        if self.enabled:
            self.web3 = Web3(Web3.HTTPProvider(RPC_URL))
            self.account = self.web3.eth.account.from_key(PRIVATE_KEY)
            self.contract = self.web3.eth.contract(
                address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                abi=CONTRACT_ABI,
            )

    @staticmethod
    def build_incident_hash(event: Dict[str, Any]) -> str:
        payload = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def anchor_event(self, event: Dict[str, Any]) -> Dict[str, Optional[str]]:
        incident_hash = self.build_incident_hash(event)

        if not self.enabled:
            return {
                "anchored": False,
                "tx_hash": None,
                "incident_hash": incident_hash,
                "error": "Blockchain not configured",
            }

        try:
            nonce = self.web3.eth.get_transaction_count(self.account.address)
            tx = self.contract.functions.storeIncident(bytes.fromhex(incident_hash)).build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "gas": 200000,
                "gasPrice": self.web3.eth.gas_price,
            })

            signed_tx = self.web3.eth.account.sign_transaction(tx, private_key=PRIVATE_KEY)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            return {
                "anchored": True,
                "tx_hash": tx_hash.hex(),
                "incident_hash": incident_hash,
                "error": None,
            }
        except Exception as exc:
            return {
                "anchored": False,
                "tx_hash": None,
                "incident_hash": incident_hash,
                "error": str(exc),
            }
