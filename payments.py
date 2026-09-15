import os
import uuid
import requests
from decimal import Decimal


PAYSTACK_SECRET_KEY = os.getenv("PAYSTACK_SECRET_KEY", "").strip()
FLW_SECRET_KEY = os.getenv("FLW_SECRET_KEY", "").strip()

PAYSTACK_URL = "https://api.paystack.co"
FLW_URL = "https://api.flutterwave.com/v3"


def new_reference(prefix="VKY"):
    return f"{prefix}-{uuid.uuid4().hex}"


def paystack_headers():
    if not PAYSTACK_SECRET_KEY:
        raise RuntimeError("PAYSTACK_SECRET_KEY is not configured")

    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def flutterwave_headers():
    if not FLW_SECRET_KEY:
        raise RuntimeError("FLW_SECRET_KEY is not configured")

    return {
        "Authorization": f"Bearer {FLW_SECRET_KEY}",
        "Content-Type": "application/json",
    }


def paystack_initialize(
    email,
    amount,
    currency,
    reference,
    callback_url,
    user_id=None,
):
    payload = {
        "email": email,
        "amount": str(int(Decimal(str(amount)) * 100)),
        "currency": currency,
        "reference": reference,
        "callback_url": callback_url,
    }

    if user_id is not None:
        payload["metadata"] = {
            "user_id": str(user_id),
            "platform": "Vicky Earn",
        }

    response = requests.post(
        f"{PAYSTACK_URL}/transaction/initialize",
        json=payload,
        headers=paystack_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def paystack_verify(reference):
    response = requests.get(
        f"{PAYSTACK_URL}/transaction/verify/{reference}",
        headers=paystack_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def paystack_create_recipient(
    name,
    account_number,
    bank_code,
    currency="NGN",
):
    payload = {
        "type": "nuban" if currency == "NGN" else "bank",
        "name": name,
        "account_number": account_number,
        "bank_code": bank_code,
        "currency": currency,
    }

    response = requests.post(
        f"{PAYSTACK_URL}/transferrecipient",
        json=payload,
        headers=paystack_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def paystack_transfer(
    recipient_code,
    amount,
    currency,
    reference,
    reason="Vicky Earn withdrawal",
):
    payload = {
        "source": "balance",
        "amount": int(Decimal(str(amount)) * 100),
        "recipient": recipient_code,
        "reason": reason,
        "reference": reference,
    }

    response = requests.post(
        f"{PAYSTACK_URL}/transfer",
        json=payload,
        headers=paystack_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def paystack_verify_transfer(reference):
    response = requests.get(
        f"{PAYSTACK_URL}/transfer/verify/{reference}",
        headers=paystack_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def flutterwave_verify_transaction(transaction_id):
    response = requests.get(
        f"{FLW_URL}/transactions/{transaction_id}/verify",
        headers=flutterwave_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def flutterwave_transfer(
    account_bank,
    account_number,
    amount,
    currency,
    reference,
    beneficiary_name,
):
    payload = {
        "account_bank": account_bank,
        "account_number": account_number,
        "amount": amount,
        "currency": currency,
        "beneficiary_name": beneficiary_name,
        "reference": reference,
        "narration": "Vicky Earn withdrawal",
    }

    response = requests.post(
        f"{FLW_URL}/transfers",
        json=payload,
        headers=flutterwave_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def flutterwave_verify_transfer(transfer_id):
    response = requests.get(
        f"{FLW_URL}/transfers/{transfer_id}",
        headers=flutterwave_headers(),
        timeout=30,
    )

    response.raise_for_status()
    return response.json()
