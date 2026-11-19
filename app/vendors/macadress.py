"""macadress.com: the MAC address analysis (vendor, device category, randomization),
read by the OpenCTI macadress enrichment connector."""

from fastapi import APIRouter, HTTPException

from app.fake import fake

HOSTS = ["api.macadress.com"]
router = APIRouter(prefix="/macadress", tags=["macadress.com"])

# OUI -> (organization, country, device category)
VENDORS = {
    "F0:18:98": ("Apple, Inc.", "US", "smartphone"),
    "3C:5A:B4": ("Google, Inc.", "US", "smart_speaker"),
    "B8:27:EB": ("Raspberry Pi Foundation", "GB", "single_board_computer"),
}


@router.get("/v1/mac/{mac}")
async def lookup(mac: str) -> dict:
    """The analysis of a MAC address: registered vendors by OUI, any other as random."""
    octets = mac.replace("-", ":").upper().split(":")
    if len(octets) != 6 or not all(len(o) == 2 for o in octets):
        raise HTTPException(status_code=400, detail="invalid MAC address")
    prefix = ":".join(octets[:3])
    vendor = VENDORS.get(prefix)
    local = bool(int(octets[0], 16) & 0x02)
    if vendor is None:
        vendor = (fake.company(), fake.country_code(), "unknown")
    organization, country, category = vendor
    return {
        "mac": ":".join(octets),
        "valid": True,
        "organization": organization,
        "country": country,
        "block_type": "MA-L",
        "matched_prefix": prefix,
        "registered": True,
        "locally_administered": local,
        "potentially_randomized": local,
        "randomization_confidence": "likely" if local else "none",
        "vendor_lookup_reliable": not local,
        "explanation": f"Universally administered unicast address registered to "
        f"{organization}.",
        "device": {"category": category, "confidence": "medium"},
        "virtualization": {"detected": False, "platform": None},
        "special_use": {"detected": False, "type": None},
        "local_vendor_derivation": {"detected": False},
        "vendor": {
            "lookup_url": "https://macadress.com/vendor/"
            + organization.lower().replace(", ", "-").replace(" ", "-").replace(".", "")
        },
    }
