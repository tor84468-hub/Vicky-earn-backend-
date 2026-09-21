import secrets
from decimal import Decimal


def _amount(value):
    amount = Decimal(str(value))
    if amount <= 0:
        raise ValueError("Amount must be greater than zero")
    return amount


def ensure_wallet(db, user_id, currency):
    currency = str(currency).upper()

    row = db.execute(
        """
        SELECT id, user_id, currency, available_balance,
               reserved_balance, status
        FROM wallet_accounts
        WHERE user_id = ?
          AND currency = ?
        """,
        (user_id, currency),
    ).fetchone()

    if row:
        return row

    db.execute(
        """
        INSERT INTO wallet_accounts
        (user_id, currency)
        VALUES (?, ?)
        """,
        (user_id, currency),
    )

    return db.execute(
        """
        SELECT id, user_id, currency, available_balance,
               reserved_balance, status
        FROM wallet_accounts
        WHERE user_id = ?
          AND currency = ?
        """,
        (user_id, currency),
    ).fetchone()


def create_ledger_transaction(
    db,
    transaction_type,
    description=None,
    reference=None,
    idempotency_key=None,
):
    transaction_uuid = secrets.token_hex(16)

    row = db.execute(
        """
        INSERT INTO ledger_transactions
        (
            transaction_uuid,
            transaction_type,
            status,
            reference,
            description,
            idempotency_key
        )
        VALUES (?, ?, 'posted', ?, ?, ?)
        RETURNING id, transaction_uuid
        """,
        (
            transaction_uuid,
            transaction_type,
            reference,
            description,
            idempotency_key,
        ),
    ).fetchone()

    return row


def add_entry(
    db,
    ledger_transaction_id,
    wallet_account_id,
    entry_type,
    amount,
    currency,
):
    amount = _amount(amount)

    if entry_type not in ("debit", "credit"):
        raise ValueError("Invalid ledger entry type")

    db.execute(
        """
        INSERT INTO ledger_entries
        (
            ledger_transaction_id,
            wallet_account_id,
            entry_type,
            amount,
            currency
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            ledger_transaction_id,
            wallet_account_id,
            entry_type,
            amount,
            str(currency).upper(),
        ),
    )


def post_balanced_transaction(
    db,
    transaction_type,
    entries,
    description=None,
    reference=None,
    idempotency_key=None,
):
    """
    Post a balanced financial transaction.

    entries:
        [
            {
                "wallet_account_id": 1,
                "entry_type": "debit",
                "amount": 100,
                "currency": "NGN"
            },
            {
                "wallet_account_id": 2,
                "entry_type": "credit",
                "amount": 100,
                "currency": "NGN"
            }
        ]

    For the same currency, total debits must equal total credits.
    """

    if not entries:
        raise ValueError("Ledger transaction requires entries")

    debit_totals = {}
    credit_totals = {}

    for entry in entries:
        currency = str(entry["currency"]).upper()
        amount = _amount(entry["amount"])
        entry_type = entry["entry_type"]

        totals = (
            debit_totals
            if entry_type == "debit"
            else credit_totals
            if entry_type == "credit"
            else None
        )

        if totals is None:
            raise ValueError("Invalid ledger entry type")

        totals[currency] = totals.get(currency, Decimal("0")) + amount

    currencies = set(debit_totals) | set(credit_totals)

    for currency in currencies:
        if debit_totals.get(currency, Decimal("0")) != credit_totals.get(
            currency,
            Decimal("0"),
        ):
            raise ValueError(
                f"Unbalanced ledger transaction for {currency}"
            )

    tx = create_ledger_transaction(
        db,
        transaction_type=transaction_type,
        description=description,
        reference=reference,
        idempotency_key=idempotency_key,
    )

    for entry in entries:
        add_entry(
            db,
            tx["id"],
            entry["wallet_account_id"],
            entry["entry_type"],
            entry["amount"],
            entry["currency"],
        )

    return tx


def credit_wallet(
    db,
    user_id,
    currency,
    amount,
    transaction_type,
    description=None,
    reference=None,
    idempotency_key=None,
):
    amount = _amount(amount)
    wallet = ensure_wallet(db, user_id, currency)

    tx = create_ledger_transaction(
        db,
        transaction_type=transaction_type,
        description=description,
        reference=reference,
        idempotency_key=idempotency_key,
    )

    add_entry(
        db,
        tx["id"],
        wallet["id"],
        "credit",
        amount,
        currency,
    )

    db.execute(
        """
        UPDATE wallet_accounts
        SET available_balance = available_balance + ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (amount, wallet["id"]),
    )

    return tx


def debit_wallet(
    db,
    user_id,
    currency,
    amount,
    transaction_type,
    description=None,
    reference=None,
    idempotency_key=None,
):
    amount = _amount(amount)
    wallet = ensure_wallet(db, user_id, currency)

    result = db.execute(
        """
        UPDATE wallet_accounts
        SET available_balance = available_balance - ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND available_balance >= ?
          AND status = 'active'
        """,
        (amount, wallet["id"], amount),
    )

    if result.rowcount != 1:
        raise ValueError("Insufficient balance")

    tx = create_ledger_transaction(
        db,
        transaction_type=transaction_type,
        description=description,
        reference=reference,
        idempotency_key=idempotency_key,
    )

    add_entry(
        db,
        tx["id"],
        wallet["id"],
        "debit",
        amount,
        currency,
    )

    return tx
