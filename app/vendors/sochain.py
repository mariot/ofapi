"""SoChain: blockchain address summary and address poisoning (sochain connector)."""

import time

from fastapi import APIRouter

from app.fake import fake

HOSTS = ["sochain.com"]
router = APIRouter(prefix="/sochain", tags=["SoChain"])


def _block(days_ago: int) -> dict:
    return {
        "height": fake.random_int(700_000, 900_000),
        "time": int(time.time()) - days_ago * 86400,
    }


@router.get("/api/v3/address_summary/{network}/{address}")
async def address_summary(network: str, address: str) -> dict:
    """Balances, transaction counts and first and last activity of an address."""
    sent = fake.random_int(1, 40)
    received = fake.random_int(1, 40)
    return {
        "status": "success",
        "data": {
            "network": network,
            "address": address,
            "confirmed_balance": f"{fake.random_int(0, 500) / 100:.8f}",
            "unconfirmed_balance": "0.00000000",
            "confirmed_received": f"{fake.random_int(500, 5000) / 100:.8f}",
            "txs_total": sent + received,
            "txs_sent": sent,
            "txs_received": received,
            "first_active": _block(900),
            "last_active": _block(3),
        },
    }


@router.get("/api/v3/address_poisoning/{network}/{address}")
async def address_poisoning(network: str, address: str) -> dict:
    """Look-alike addresses that sent the address dust."""
    findings = [
        {
            "sender": fake.bothify("1" + "?" * 33, letters="abcdefghjkmnpqrstuvwxyz"),
            "imitates": address[:4] + "..." + address[-4:],
            "dust_txid": fake.sha256(),
            "amount": "0.00000546",
            "height": fake.random_int(800_000, 900_000),
        }
        for _ in range(2)
    ]
    return {
        "status": "success",
        "data": {"network": network, "address": address, "findings": findings},
    }
