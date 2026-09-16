import json
import os
import psycopg
import cloudinary
import cloudinary.uploader

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from database import init_db, get_db, transaction, generate_account_id
from vickycoin_config import vic_enabled, vic_get_balance, vic_get_transaction, vic_get_status

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers.exceptions import (
    InvalidRegistrationResponse,
    InvalidAuthenticationResponse,
)
import base64

def bytes_to_base64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

from webauthn_config import (
    WEBAUTHN_RP_ID,
    WEBAUTHN_RP_NAME,
    WEBAUTHN_ORIGIN,
    ADMIN_WEBAUTHN_RP_ID,
    ADMIN_WEBAUTHN_RP_NAME,
    ADMIN_WEBAUTHN_ORIGIN,
)

app = Flask(__name__)
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": "*"
        }
    },
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Admin-Token"]
)

init_db()


# ============================================================
# HELPERS
# ============================================================

SUPPORTED_CURRENCIES = {
    "NGN": {"name": "Nigerian Naira", "symbol": "₦", "flag": "🇳🇬"},
    "USD": {"name": "US Dollar", "symbol": "$", "flag": "🇺🇸"},
    "EUR": {"name": "Euro", "symbol": "€", "flag": "🇪🇺"},
    "GBP": {"name": "British Pound", "symbol": "£", "flag": "🇬🇧"},
    "GHS": {"name": "Ghanaian Cedi", "symbol": "₵", "flag": "🇬🇭"},
    "XOF": {"name": "West African CFA Franc", "symbol": "CFA", "flag": "🌍"},
    "CAD": {"name": "Canadian Dollar", "symbol": "C$", "flag": "🇨🇦"},
    "VIC": {"name": "Vicky Coin", "symbol": "VIC", "flag": "🪙"},
}

# Fallback rates.
# 1 unit of each currency expressed in USD.
FX_TO_USD = {
    "USD": 1.0,
    "EUR": 1.17,
    "GBP": 1.35,
    "CAD": 0.73,
    "GHS": 0.062,
    "NGN": 0.00062,
    "XOF": 0.00162,
}


def parse_amount(value):
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return None

    if amount <= 0:
        return None

    return round(amount, 2)


def convert_currency(amount, from_currency, to_currency):
    from_currency = from_currency.upper()
    to_currency = to_currency.upper()

    if from_currency not in FX_TO_USD:
        raise ValueError("Unsupported source currency")

    if to_currency not in FX_TO_USD:
        raise ValueError("Unsupported destination currency")

    usd_amount = float(amount) * FX_TO_USD[from_currency]
    converted = usd_amount / FX_TO_USD[to_currency]

    return round(converted, 2)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "success": True,
        "message": "Welcome to Vicky Earn API"
    })


# ============================================================
# AUTH
# ============================================================

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    if not name or not email:
        return jsonify({
            "success": False,
            "message": "Name and email are required"
        }), 400

    # The database still requires a password column for legacy compatibility,
    # but normal users never receive or use this generated value for login.
    password_hash = generate_password_hash(
        secrets.token_urlsafe(32)
    )

    try:
        with transaction() as db:
            existing = db.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing:
                return jsonify({
                    "success": False,
                    "message": "An account with this email already exists. Please log in."
                }), 409

            account_id = generate_account_id(db)

            cursor = db.execute(
                """
                INSERT INTO users
                (name, email, password, account_id)
                VALUES (?, ?, ?, ?)
                """,
                (name, email, password_hash, account_id)
            )

            user_id = cursor.lastrowid

        # Create the initial session only so the new account can
        # register its phone security credential immediately.
        session_token = create_user_session(user_id)

        return jsonify({
            "success": True,
            "message": "Account created successfully",
            "session_token": session_token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "balance": 0,
                "account_id": account_id
            }
        }), 201

    except psycopg.IntegrityError as e:
        return jsonify({
            "success": False,
            "message": "Email or account ID already exists",
            "error": str(e)
        }), 409
    except Exception as e:
        app.logger.exception("Registration failed")
        return jsonify({
            "success": False,
            "message": "Account could not be created",
            "error": str(e)
        }), 500



def create_user_session(user_id):
    """
    Create a long-lived Vicky Earn login session.

    Each device receives its own token. The token is stored
    server-side, allowing the login to survive browser/app
    restarts and remain available across devices.
    """

    token = secrets.token_urlsafe(64)

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO user_sessions
                (user_id, token, expires_at, last_used_at)
            VALUES
                (?, ?, CURRENT_TIMESTAMP + INTERVAL '10 years',
                 CURRENT_TIMESTAMP)
            """,
            (user_id, token)
        )

        db.commit()
        return token

    finally:
        db.close()


@app.route("/api/auth/login", methods=["POST"])
def login():
    return jsonify({
        "success": False,
        "message": "Password login is disabled. Use your phone fingerprint, face unlock, or secure phone PIN."
    }), 410


@app.route("/api/auth/session", methods=["GET"])
def restore_session():
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    token = auth[7:].strip()

    if not token:
        return jsonify({
            "success": False,
            "message": "Invalid session"
        }), 401

    db = get_db()

    try:
        session = db.execute(
            """
            SELECT
                s.user_id,
                u.name,
                u.email,
                u.balance,
                u.currency,
                u.account_id
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
              AND s.expires_at > CURRENT_TIMESTAMP
            """,
            (token,)
        ).fetchone()

        if not session:
            return jsonify({
                "success": False,
                "message": "Session expired"
            }), 401

        db.execute(
            """
            UPDATE user_sessions
            SET last_used_at = CURRENT_TIMESTAMP,
                expires_at = CURRENT_TIMESTAMP + INTERVAL '365 days'
            WHERE token = ?
            """,
            (token,)
        )

        db.commit()

        return jsonify({
            "success": True,
            "user": {
                "id": session["user_id"],
                "name": session["name"],
                "email": session["email"],
                "balance": session["balance"],
                "currency": session["currency"],
                "account_id": session["account_id"]
            }
        })

    finally:
        db.close()


@app.route("/api/auth/logout", methods=["POST"])
def user_logout():
    auth = request.headers.get("Authorization", "")

    if auth.startswith("Bearer "):
        token = auth[7:].strip()

        if token:
            db = get_db()

            try:
                db.execute(
                    "DELETE FROM user_sessions WHERE token = ?",
                    (token,)
                )
                db.commit()
            finally:
                db.close()

    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


# ============================================================
# EARNINGS
# ============================================================

@app.route("/api/earn/daily-bonus", methods=["POST"])
def daily_bonus():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")

    if not user_id:
        return jsonify({
            "success": False,
            "message": "User ID is required"
        }), 400

    bonus = 10

    try:
        with transaction() as db:
            user = db.execute(
                """
                SELECT id, balance, currency
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "User not found"
                }), 404

            claimed = db.execute(
                """
                SELECT id
                FROM transactions
                WHERE user_id = ?
                  AND type = 'daily_bonus'
                  AND date(created_at) = date('now')
                LIMIT 1
                """,
                (user_id,)
            ).fetchone()

            if claimed:
                return jsonify({
                    "success": False,
                    "message": "Daily bonus already claimed today"
                }), 409

            update = db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (bonus, user_id)
            )

            if update.rowcount != 1:
                raise RuntimeError("Daily bonus balance update failed")

            new_balance = db.execute(
                "SELECT balance FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()["balance"]

            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, description, currency)
                VALUES (?, 'daily_bonus', ?, ?, ?)
                """,
                (
                    user_id,
                    bonus,
                    "Daily bonus",
                    user["currency"]
                )
            )

            db.execute(
                """
                INSERT INTO notifications
                (user_id, title, message)
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    "Daily bonus 🎉",
                    f"You earned {bonus:g} {user['currency']} from your daily bonus."
                )
            )

        return jsonify({
            "success": True,
            "message": "Daily bonus claimed successfully",
            "amount": bonus,
            "balance": new_balance
        })

    except Exception:
        app.logger.exception("Daily bonus transaction failed")
        return jsonify({
            "success": False,
            "message": "Unable to process daily bonus"
        }), 500


@app.route("/api/earn/tasks", methods=["GET"])
def get_tasks():
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT id, title, description, reward, active
            FROM tasks
            WHERE active = 1
            ORDER BY id
            """
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "tasks": [dict(row) for row in rows]
    })


@app.route("/api/earn/tasks/complete", methods=["POST"])
def complete_task():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    task_id = data.get("task_id")

    if not user_id or not task_id:
        return jsonify({
            "success": False,
            "message": "User ID and task ID are required"
        }), 400

    try:
        with transaction() as db:
            user = db.execute(
                """
                SELECT id, balance, currency
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "User not found"
                }), 404

            task = db.execute(
                """
                SELECT id, title, reward
                FROM tasks
                WHERE id = ? AND active = 1
                """,
                (task_id,)
            ).fetchone()

            if not task:
                return jsonify({
                    "success": False,
                    "message": "Task not found"
                }), 404

            description = f"Task: {task['title']}"

            already_done = db.execute(
                """
                SELECT id
                FROM transactions
                WHERE user_id = ?
                  AND type = 'task'
                  AND description = ?
                LIMIT 1
                """,
                (user_id, description)
            ).fetchone()

            if already_done:
                return jsonify({
                    "success": False,
                    "message": "Task already completed"
                }), 409

            reward = parse_amount(task["reward"])

            if reward is None:
                return jsonify({
                    "success": False,
                    "message": "Invalid task reward"
                }), 400

            update = db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (reward, user_id)
            )

            if update.rowcount != 1:
                raise RuntimeError("Task balance update failed")

            new_balance = db.execute(
                "SELECT balance FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()["balance"]

            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, description, currency)
                VALUES (?, 'task', ?, ?, ?)
                """,
                (
                    user_id,
                    reward,
                    description,
                    user["currency"]
                )
            )

            db.execute(
                """
                INSERT INTO notifications
                (user_id, title, message)
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    "Task completed 🎉",
                    f"You earned {reward:g} {user['currency']} from {task['title']}."
                )
            )

        return jsonify({
            "success": True,
            "message": "Task completed successfully",
            "amount": reward,
            "balance": new_balance
        })

    except Exception:
        app.logger.exception("Task transaction failed")
        return jsonify({
            "success": False,
            "message": "Unable to process task reward"
        }), 500


# ============================================================
# CURRENCY
# ============================================================

@app.route("/api/currencies", methods=["GET"])
def currencies():
    return jsonify({
        "success": True,
        "currencies": SUPPORTED_CURRENCIES
    })


@app.route("/api/user/currency", methods=["POST"])
def update_currency():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    currency = str(data.get("currency", "")).upper()

    if not user_id:
        return jsonify({
            "success": False,
            "message": "User ID is required"
        }), 400

    if currency not in SUPPORTED_CURRENCIES:
        return jsonify({
            "success": False,
            "message": "Unsupported currency"
        }), 400

    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email, balance, currency, avatar_url
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

        if not user:
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404

        db.execute(
            "UPDATE users SET currency = ? WHERE id = ?",
            (currency, user_id)
        )

        db.commit()

        updated = db.execute(
            """
            SELECT id, name, email, balance, currency
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

    finally:
        db.close()

    return jsonify({
        "success": True,
        "message": "Currency updated successfully",
        "user": dict(updated)
    })


# ============================================================
# WALLET
# ============================================================

@app.route("/api/wallet/<int:user_id>", methods=["GET"])
def wallet(user_id):
    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email, account_id, balance, currency
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()
    finally:
        db.close()

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    return jsonify({
        "success": True,
        "wallet": dict(user)
    })


# ============================================================
# WITHDRAWAL
# ============================================================

@app.route("/api/wallet/withdraw", methods=["POST"])
def withdraw():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    amount = parse_amount(data.get("amount"))
    method = str(data.get("method", "")).strip()
    account = str(data.get("account", "")).strip()

    if not user_id or amount is None or not method or not account:
        return jsonify({
            "success": False,
            "message": "User ID, amount, method and account are required"
        }), 400

    try:
        with transaction() as db:
            user = db.execute(
                """
                SELECT id, balance, currency
                FROM users
                WHERE id = ?
                """,
                (user_id,)
            ).fetchone()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "User not found"
                }), 404

            # Atomic balance deduction.
            update = db.execute(
                """
                UPDATE users
                SET balance = balance - ?
                WHERE id = ?
                  AND balance >= ?
                """,
                (amount, user_id, amount)
            )

            if update.rowcount != 1:
                return jsonify({
                    "success": False,
                    "message": "Insufficient balance"
                }), 400

            new_balance = db.execute(
                "SELECT balance FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()["balance"]

            cursor = db.execute(
                """
                INSERT INTO withdrawals
                (user_id, amount, currency, method, account, status)
                VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (
                    user_id,
                    amount,
                    user["currency"],
                    method,
                    account
                )
            )

            withdrawal_id = cursor.lastrowid

            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, description, currency)
                VALUES (?, 'withdrawal', ?, ?, ?)
                """,
                (
                    user_id,
                    -amount,
                    f"Withdrawal via {method}",
                    user["currency"]
                )
            )

            db.execute(
                """
                INSERT INTO notifications
                (user_id, title, message)
                VALUES (?, ?, ?)
                """,
                (
                    user_id,
                    "Withdrawal requested",
                    f"Your withdrawal of {amount:g} {user['currency']} is pending."
                )
            )

        return jsonify({
            "success": True,
            "message": "Withdrawal request submitted",
            "withdrawal_id": withdrawal_id,
            "amount": amount,
            "balance": new_balance,
            "status": "pending"
        })

    except Exception:
        app.logger.exception("Withdrawal transaction failed")
        return jsonify({
            "success": False,
            "message": "Unable to process withdrawal"
        }), 500


# ============================================================
# TRANSFER
# ============================================================

@app.route("/api/transfer/recipient", methods=["POST"])
def transfer_recipient():
    data = request.get_json(silent=True) or {}

    account_id = str(
        data.get("account_id", data.get("recipient_account_id", ""))
    ).strip().upper()

    if not account_id:
        return jsonify({
            "success": False,
            "message": "Recipient Account ID is required"
        }), 400

    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, account_id, currency
            FROM users
            WHERE account_id = ?
            """,
            (account_id,)
        ).fetchone()
    finally:
        db.close()

    if not user:
        return jsonify({
            "success": False,
            "message": "Recipient Account ID not found"
        }), 404

    return jsonify({
        "success": True,
        "recipient": {
            "name": user["name"],
            "account_id": user["account_id"],
            "currency": user["currency"]
        }
    })


@app.route("/api/transfer/quote", methods=["POST"])
def transfer_quote():
    data = request.get_json(silent=True) or {}

    sender_account_id = str(
        data.get("account_id", "")
    ).strip().upper()

    recipient_account_id = str(
        data.get("recipient_account_id", "")
    ).strip().upper()

    amount = parse_amount(data.get("amount"))

    if not sender_account_id or not recipient_account_id or amount is None:
        return jsonify({
            "success": False,
            "message": "Account IDs and a valid amount are required"
        }), 400

    db = get_db()

    try:
        sender = db.execute(
            """
            SELECT id, name, account_id, balance, currency
            FROM users
            WHERE account_id = ?
            """,
            (sender_account_id,)
        ).fetchone()

        recipient = db.execute(
            """
            SELECT id, name, account_id, currency
            FROM users
            WHERE account_id = ?
            """,
            (recipient_account_id,)
        ).fetchone()
    finally:
        db.close()

    if not sender:
        return jsonify({
            "success": False,
            "message": "Sender Account ID not found"
        }), 404

    if not recipient:
        return jsonify({
            "success": False,
            "message": "Recipient Account ID not found"
        }), 404

    if sender["id"] == recipient["id"]:
        return jsonify({
            "success": False,
            "message": "You cannot transfer to yourself"
        }), 400

    if amount > float(sender["balance"]):
        return jsonify({
            "success": False,
            "message": "Insufficient balance"
        }), 400

    try:
        received_amount = convert_currency(
            amount,
            sender["currency"],
            recipient["currency"]
        )
    except ValueError as exc:
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 400

    recipient_per_sender = (
        FX_TO_USD[sender["currency"]]
        / FX_TO_USD[recipient["currency"]]
    )

    return jsonify({
        "success": True,
        "quote": {
            "sender": {
                "name": sender["name"],
                "account_id": sender["account_id"],
                "currency": sender["currency"]
            },
            "recipient": {
                "name": recipient["name"],
                "account_id": recipient["account_id"],
                "currency": recipient["currency"]
            },
            "send_amount": amount,
            "send_currency": sender["currency"],
            "receive_amount": received_amount,
            "receive_currency": recipient["currency"],
            "rate": round(recipient_per_sender, 8)
        }
    })


@app.route("/api/transfer", methods=["POST"])
def transfer_money():
    data = request.get_json(silent=True) or {}

    sender_account_id = str(
        data.get("account_id", "")
    ).strip().upper()

    recipient_account_id = str(
        data.get("recipient_account_id", "")
    ).strip().upper()

    amount = parse_amount(data.get("amount"))

    if not sender_account_id or not recipient_account_id or amount is None:
        return jsonify({
            "success": False,
            "message": "Sender Account ID, recipient Account ID and amount are required"
        }), 400

    if sender_account_id == recipient_account_id:
        return jsonify({
            "success": False,
            "message": "You cannot transfer to yourself"
        }), 400

    try:
        with transaction() as db:
            sender = db.execute(
                """
                SELECT id, name, email, account_id, balance, currency
                FROM users
                WHERE account_id = ?
                """,
                (sender_account_id,)
            ).fetchone()

            recipient = db.execute(
                """
                SELECT id, name, email, account_id, balance, currency
                FROM users
                WHERE account_id = ?
                """,
                (recipient_account_id,)
            ).fetchone()

            if not sender:
                return jsonify({
                    "success": False,
                    "message": "Sender Account ID not found"
                }), 404

            if not recipient:
                return jsonify({
                    "success": False,
                    "message": "Recipient Account ID not found"
                }), 404

            if sender["id"] == recipient["id"]:
                return jsonify({
                    "success": False,
                    "message": "You cannot transfer to yourself"
                }), 400

            sender_currency = sender["currency"]
            recipient_currency = recipient["currency"]

            received_amount = convert_currency(
                amount,
                sender_currency,
                recipient_currency
            )

            rate = (
                FX_TO_USD[sender_currency]
                / FX_TO_USD[recipient_currency]
            )

            # Atomic sender debit.
            debit = db.execute(
                """
                UPDATE users
                SET balance = balance - ?
                WHERE id = ?
                  AND balance >= ?
                """,
                (amount, sender["id"], amount)
            )

            if debit.rowcount != 1:
                return jsonify({
                    "success": False,
                    "message": "Insufficient balance"
                }), 400

            # Recipient credit happens in the same transaction.
            credit = db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (received_amount, recipient["id"])
            )

            if credit.rowcount != 1:
                raise RuntimeError("Recipient credit failed")

            sender_balance = db.execute(
                "SELECT balance FROM users WHERE id = ?",
                (sender["id"],)
            ).fetchone()["balance"]

            recipient_balance = db.execute(
                "SELECT balance FROM users WHERE id = ?",
                (recipient["id"],)
            ).fetchone()["balance"]

            # Sender transaction.
            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, description, currency)
                VALUES (?, 'transfer_sent', ?, ?, ?)
                """,
                (
                    sender["id"],
                    -amount,
                    (
                        f"Transfer to {recipient['name']} "
                        f"({recipient['account_id']}) - "
                        f"received {received_amount:g} {recipient_currency}"
                    ),
                    sender_currency
                )
            )

            # Receiver transaction.
            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, description, currency)
                VALUES (?, 'transfer_received', ?, ?, ?)
                """,
                (
                    recipient["id"],
                    received_amount,
                    (
                        f"Transfer from {sender['name']} "
                        f"({sender['account_id']}) - "
                        f"sent {amount:g} {sender_currency}"
                    ),
                    recipient_currency
                )
            )

            # Recipient notification.
            db.execute(
                """
                INSERT INTO notifications
                (user_id, title, message)
                VALUES (?, ?, ?)
                """,
                (
                    recipient["id"],
                    "Money received 💰",
                    (
                        f"You received {received_amount:g} "
                        f"{recipient_currency} from {sender['name']} "
                        f"({sender['account_id']})."
                    )
                )
            )

        return jsonify({
            "success": True,
            "message": "Transfer successful",
            "sender": {
                "name": sender["name"],
                "account_id": sender["account_id"],
                "currency": sender_currency,
                "amount": amount,
                "balance": sender_balance
            },
            "recipient": {
                "name": recipient["name"],
                "account_id": recipient["account_id"],
                "currency": recipient_currency,
                "amount": received_amount,
                "balance": recipient_balance
            },
            "exchange_rate": round(rate, 8)
        })

    except Exception:
        app.logger.exception("Transfer transaction failed")
        return jsonify({
            "success": False,
            "message": "Unable to process transfer"
        }), 500


# ============================================================
# TRANSACTIONS
# ============================================================

@app.route("/api/transactions/<int:user_id>", methods=["GET"])
def transactions(user_id):
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT id, type, amount, description, currency, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,)
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "transactions": [dict(row) for row in rows]
    })


# ============================================================
# REFERRALS
# ============================================================

@app.route("/api/referrals/<int:user_id>", methods=["GET"])
def referrals(user_id):
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT id, referred_user_id, referral_code, reward, created_at
            FROM referrals
            WHERE user_id = ?
            ORDER BY id DESC
            """,
            (user_id,)
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "referrals": [dict(row) for row in rows]
    })


# ============================================================
# NOTIFICATIONS
# ============================================================

@app.route("/api/notifications/<int:user_id>", methods=["GET"])
def notifications(user_id):
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT id, title, message, read, created_at
            FROM notifications
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 50
            """,
            (user_id,)
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "notifications": [dict(row) for row in rows]
    })


@app.route("/api/notifications/<int:notification_id>/read", methods=["POST"])
def mark_notification_read(notification_id):
    db = get_db()

    try:
        cursor = db.execute(
            "UPDATE notifications SET read = 1 WHERE id = ?",
            (notification_id,)
        )

        db.commit()
    finally:
        db.close()

    if cursor.rowcount == 0:
        return jsonify({
            "success": False,
            "message": "Notification not found"
        }), 404

    return jsonify({
        "success": True,
        "message": "Notification marked as read"
    })


# ============================================================
# CLOUDINARY CONFIG
# ============================================================
cloudinary.config(
    cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME", ""),
    api_key=os.environ.get("CLOUDINARY_API_KEY", ""),
    api_secret=os.environ.get("CLOUDINARY_API_SECRET", ""),
)

# PROFILE PICTURE UPLOAD
# ============================================================
@app.route("/api/profile/<int:user_id>/avatar", methods=["POST"])
def upload_profile_avatar(user_id):
    if not os.environ.get("CLOUDINARY_CLOUD_NAME") or not os.environ.get("CLOUDINARY_API_KEY") or not os.environ.get("CLOUDINARY_API_SECRET"):
        return jsonify({
            "success": False,
            "message": "Profile image storage is not configured."
        }), 500

    if "avatar" not in request.files:
        return jsonify({
            "success": False,
            "message": "No profile picture was uploaded."
        }), 400

    file = request.files["avatar"]

    if not file or not file.filename:
        return jsonify({
            "success": False,
            "message": "Please select a profile picture."
        }), 400

    allowed_types = {
        "image/jpeg",
        "image/png",
        "image/webp"
    }

    if file.mimetype not in allowed_types:
        return jsonify({
            "success": False,
            "message": "Only JPG, PNG, and WebP images are allowed."
        }), 400

    try:
        result = cloudinary.uploader.upload(
            file,
            folder="vicky-earn/profiles",
            resource_type="image",
            transformation=[
                {
                    "width": 500,
                    "height": 500,
                    "crop": "fill",
                    "gravity": "face"
                }
            ]
        )

        avatar_url = result.get("secure_url")

        if not avatar_url:
            raise RuntimeError("Cloudinary did not return an image URL.")

        db = get_db()

        try:
            user = db.execute(
                "SELECT id FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "User not found"
                }), 404

            db.execute(
                "UPDATE users SET avatar_url = ? WHERE id = ?",
                (avatar_url, user_id)
            )
            db.commit()

        finally:
            db.close()

        return jsonify({
            "success": True,
            "avatar_url": avatar_url,
            "message": "Profile picture updated successfully."
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": f"Profile picture upload failed: {exc}"
        }), 500


# PROFILE
# ============================================================

@app.route("/api/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email, balance, currency, avatar_url, created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()
    finally:
        db.close()

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    return jsonify({
        "success": True,
        "user": dict(user)
    })


@app.route("/api/profile/<int:user_id>", methods=["POST"])
def update_profile(user_id):
    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()

    if not name:
        return jsonify({
            "success": False,
            "message": "Name is required"
        }), 400

    db = get_db()

    try:
        user = db.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not user:
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404

        db.execute(
            "UPDATE users SET name = ? WHERE id = ?",
            (name, user_id)
        )

        db.commit()

        updated = db.execute(
            """
            SELECT id, name, email, balance, currency
            FROM users
            WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

    finally:
        db.close()

    return jsonify({
        "success": True,
        "message": "Profile updated successfully",
        "user": dict(updated)
    })



# ============================================================
# ADMIN DASHBOARD
# ============================================================

import secrets
from functools import wraps

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer "):
            return jsonify({
                "success": False,
                "message": "Admin authentication required"
            }), 401

        token = auth[7:].strip()

        db = get_db()

        try:
            session = db.execute(
                """
                SELECT admin_id
                FROM admin_sessions
                WHERE token = ?
                AND expires_at > CURRENT_TIMESTAMP
                """,
                (token,)
            ).fetchone()
        finally:
            db.close()

        if not session:
            return jsonify({
                "success": False,
                "message": "Invalid or expired admin session"
            }), 401

        return func(*args, **kwargs)

    return wrapper


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    allowed_admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()

    if not allowed_admin_email or email != allowed_admin_email:
        return jsonify({
            "success": False,
            "message": "This email is not authorized for the Vicky Earn Admin app."
        }), 403

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Admin email and password are required"
        }), 400

    db = get_db()

    try:
        admin = db.execute(
            """
            SELECT id, name, email, password, avatar_url
            FROM admins
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        if not admin or not check_password_hash(
            admin["password"],
            password
        ):
            return jsonify({
                "success": False,
                "message": "Invalid admin email or password"
            }), 401

        token = secrets.token_urlsafe(48)

        db.execute(
            """
            INSERT INTO admin_sessions
            (admin_id, token, expires_at)
            VALUES (?, ?, datetime('now', '+7 days'))
            """,
            (admin["id"], token)
        )

        db.execute(
            """
            INSERT INTO admin_audit_logs
            (admin_id, action, description)
            VALUES (?, ?, ?)
            """,
            (
                admin["id"],
                "login",
                "Admin logged into dashboard"
            )
        )

        db.commit()

        return jsonify({
            "success": True,
            "message": "Admin login successful",
            "token": token,
            "admin": {
                "id": admin["id"],
                "name": admin["name"],
                "email": admin["email"],
                "avatar_url": admin["avatar_url"]
            }
        })

    finally:
        db.close()


@app.route("/api/admin/profile/avatar", methods=["POST"])
@admin_required
def upload_admin_profile_avatar():
    if not os.environ.get("CLOUDINARY_CLOUD_NAME") or not os.environ.get("CLOUDINARY_API_KEY") or not os.environ.get("CLOUDINARY_API_SECRET"):
        return jsonify({
            "success": False,
            "message": "Profile image storage is not configured."
        }), 500

    if "avatar" not in request.files:
        return jsonify({
            "success": False,
            "message": "No profile picture was uploaded."
        }), 400

    file = request.files["avatar"]

    if not file or not file.filename:
        return jsonify({
            "success": False,
            "message": "Please select a profile picture."
        }), 400

    allowed_types = {
        "image/jpeg",
        "image/png",
        "image/webp"
    }

    if file.mimetype not in allowed_types:
        return jsonify({
            "success": False,
            "message": "Only JPG, PNG, and WebP images are allowed."
        }), 400

    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip()

    db = get_db()

    try:
        session = db.execute(
            """
            SELECT admin_id
            FROM admin_sessions
            WHERE token = ?
            AND expires_at > CURRENT_TIMESTAMP
            """,
            (token,)
        ).fetchone()

        if not session:
            return jsonify({
                "success": False,
                "message": "Admin authentication required"
            }), 401

        admin_id = session["admin_id"]

        result = cloudinary.uploader.upload(
            file,
            folder="vicky-earn/admins",
            resource_type="image",
            transformation=[
                {
                    "width": 500,
                    "height": 500,
                    "crop": "fill",
                    "gravity": "face"
                }
            ]
        )

        avatar_url = result.get("secure_url")

        if not avatar_url:
            raise RuntimeError("Cloudinary did not return an image URL.")

        db.execute(
            "UPDATE admins SET avatar_url = ? WHERE id = ?",
            (avatar_url, admin_id)
        )

        db.commit()

        return jsonify({
            "success": True,
            "avatar_url": avatar_url,
            "message": "Admin profile picture updated successfully."
        })

    except Exception as exc:
        db.rollback()
        return jsonify({
            "success": False,
            "message": f"Profile picture upload failed: {exc}"
        }), 500

    finally:
        db.close()


@app.route("/api/admin/logout", methods=["POST"])
@admin_required
def admin_logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip()

    db = get_db()

    try:
        session = db.execute(
            "SELECT admin_id FROM admin_sessions WHERE token = ?",
            (token,)
        ).fetchone()

        if session:
            db.execute(
                "DELETE FROM admin_sessions WHERE token = ?",
                (token,)
            )

            db.execute(
                """
                INSERT INTO admin_audit_logs
                (admin_id, action, description)
                VALUES (?, ?, ?)
                """,
                (
                    session["admin_id"],
                    "logout",
                    "Admin logged out"
                )
            )

        db.commit()

    finally:
        db.close()

    return jsonify({
        "success": True,
        "message": "Admin logged out"
    })


@app.route("/api/admin/dashboard", methods=["GET"])
@admin_required
def admin_dashboard():
    db = get_db()

    try:
        total_users = db.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        new_users_today = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM users
            WHERE date(created_at) = date('now')
            """
        ).fetchone()["count"]

        total_transactions = db.execute(
            "SELECT COUNT(*) AS count FROM transactions"
        ).fetchone()["count"]

        total_withdrawals = db.execute(
            "SELECT COUNT(*) AS count FROM withdrawals"
        ).fetchone()["count"]

        pending_withdrawals = db.execute(
            """
            SELECT COUNT(*) AS count
            FROM withdrawals
            WHERE status = 'pending'
            """
        ).fetchone()["count"]

        total_balance = db.execute(
            """
            SELECT COALESCE(SUM(balance), 0) AS total
            FROM users
            """
        ).fetchone()["total"]

        platform_revenue = db.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM platform_revenue
            """
        ).fetchone()["total"]

        users = db.execute(
            """
            SELECT id, name, email, balance,
                   currency, account_id, created_at
            FROM users
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        transactions = db.execute(
            """
            SELECT
                t.id,
                t.user_id,
                u.name,
                u.email,
                t.type,
                t.amount,
                t.currency,
                t.description,
                t.created_at
            FROM transactions t
            LEFT JOIN users u ON u.id = t.user_id
            ORDER BY t.id DESC
            LIMIT 100
            """
        ).fetchall()

        withdrawals = db.execute(
            """
            SELECT
                w.id,
                w.user_id,
                u.name,
                u.email,
                w.amount,
                w.currency,
                w.method,
                w.account,
                w.status,
                w.created_at
            FROM withdrawals w
            LEFT JOIN users u ON u.id = w.user_id
            ORDER BY w.id DESC
            LIMIT 100
            """
        ).fetchall()

        revenue = db.execute(
            """
            SELECT id, type, amount, currency,
                   description, created_at
            FROM platform_revenue
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

    finally:
        db.close()

    return jsonify({
        "success": True,
        "stats": {
            "total_users": total_users,
            "new_users_today": new_users_today,
            "total_transactions": total_transactions,
            "total_withdrawals": total_withdrawals,
            "pending_withdrawals": pending_withdrawals,
            "total_balance": total_balance,
            "platform_revenue": platform_revenue
        },
        "users": [dict(row) for row in users],
        "transactions": [dict(row) for row in transactions],
        "withdrawals": [dict(row) for row in withdrawals],
        "revenue": [dict(row) for row in revenue]
    })


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def admin_users():
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT id, name, email, balance,
                   currency, account_id, created_at
            FROM users
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "users": [dict(row) for row in rows]
    })




@app.route("/api/admin/users/reset-all", methods=["POST"])
@admin_required
def admin_reset_all_users():
    db = get_db()

    try:
        # Delete dependent normal-user records first.
        db.execute("DELETE FROM transactions")
        db.execute("DELETE FROM notifications")
        db.execute("DELETE FROM withdrawals")
        db.execute("DELETE FROM referrals")
        db.execute("DELETE FROM user_sessions")
        db.execute("DELETE FROM user_webauthn_credentials")
        db.execute("DELETE FROM webauthn_challenges")

        # Delete ONLY normal user accounts.
        # The separate admins table is never modified.
        result = db.execute("DELETE FROM users")

        db.commit()

        return jsonify({
            "success": True,
            "message": "All normal user accounts have been reset",
            "deleted_accounts": result.rowcount
        })

    except Exception as exc:
        db.rollback()
        return jsonify({
            "success": False,
            "message": f"Account reset failed: {exc}"
        }), 500

    finally:
        db.close()

@app.route("/api/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email:
        return jsonify({
            "success": False,
            "message": "User email is required"
        }), 400

    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email
            FROM users
            WHERE LOWER(email) = ?
            LIMIT 1
            """,
            (email,)
        ).fetchone()

        if not user:
            return jsonify({
                "success": False,
                "message": "User account not found"
            }), 404

        user_id = user["id"]

        # Remove records that reference this user without ON DELETE CASCADE.
        db.execute("DELETE FROM transactions WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM notifications WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM withdrawals WHERE user_id = ?", (user_id,))
        db.execute(
            "DELETE FROM referrals WHERE user_id = ? OR referred_user_id = ?",
            (user_id, user_id)
        )

        # These tables already use ON DELETE CASCADE where present.
        db.execute(
            "DELETE FROM users WHERE id = ? AND LOWER(email) = ?",
            (user_id, email)
        )

        db.commit()

        return jsonify({
            "success": True,
            "message": "Normal user account deleted",
            "deleted_user": {
                "id": user_id,
                "name": user["name"],
                "email": user["email"]
            }
        })

    except Exception as exc:
        db.rollback()
        return jsonify({
            "success": False,
            "message": f"Account deletion failed: {exc}"
        }), 500

    finally:
        db.close()


@app.route("/api/admin/withdrawals", methods=["GET"])
@admin_required
def admin_withdrawals():
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT
                w.id,
                w.user_id,
                u.name,
                u.email,
                w.amount,
                w.currency,
                w.method,
                w.account,
                w.status,
                w.created_at
            FROM withdrawals w
            LEFT JOIN users u ON u.id = w.user_id
            ORDER BY w.id DESC
            """
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "withdrawals": [dict(row) for row in rows]
    })


@app.route("/api/admin/audit-logs", methods=["GET"])
@admin_required
def admin_audit_logs():
    db = get_db()

    try:
        rows = db.execute(
            """
            SELECT
                l.id,
                l.admin_id,
                a.name AS admin_name,
                a.email AS admin_email,
                l.action,
                l.description,
                l.created_at
            FROM admin_audit_logs l
            LEFT JOIN admins a ON a.id = l.admin_id
            ORDER BY l.id DESC
            LIMIT 100
            """
        ).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "logs": [dict(row) for row in rows]
    })


# ============================================================
# HEALTH / STATS
# ============================================================

@app.route("/api/health")
def health():
    db = get_db()

    try:
        db.execute("SELECT 1").fetchone()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "status": "healthy",
        "app": "Vicky Earn",
        "database": "connected"
    })


@app.route("/api/stats")
def stats():
    db = get_db()

    try:
        users = db.execute(
            "SELECT COUNT(*) AS count FROM users"
        ).fetchone()["count"]

        transactions_count = db.execute(
            "SELECT COUNT(*) AS count FROM transactions"
        ).fetchone()["count"]
    finally:
        db.close()

    return jsonify({
        "success": True,
        "users": users,
        "transactions": transactions_count
    })



# ============================================================
# ADMIN DATABASE TABLES
# ============================================================

def ensure_admin_tables():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id BIGSERIAL PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS platform_revenue (
                id BIGSERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_logs (
                id BIGSERIAL PRIMARY KEY,
                admin_id INTEGER,
                action TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()
    finally:
        db.close()


ensure_admin_tables()


# ============================================================
# VICKY EARN PROFIT ENGINE
# ============================================================

def ensure_profit_tables():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS platform_expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS revenue_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                provider TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.commit()
    finally:
        db.close()


ensure_profit_tables()




# ============================================================
# USER CROSS-DEVICE SESSIONS
# ============================================================

def ensure_user_session_table():
    db = get_db()

    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        db.commit()
    finally:
        db.close()


ensure_user_session_table()


# ============================================================
# USER WEBAUTHN / PASSKEY CREDENTIALS
# ============================================================

def ensure_user_webauthn_table():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count BIGINT NOT NULL DEFAULT 0,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.commit()
    finally:
        db.close()

ensure_user_webauthn_table()


def ensure_webauthn_challenge_table():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT,
                challenge TEXT UNIQUE NOT NULL,
                ceremony TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.commit()
    finally:
        db.close()

ensure_webauthn_challenge_table()


# ============================================================
# USER SECURITY / NOTIFICATION TABLES
# ============================================================

def ensure_user_security_tables():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS user_security_events (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                event_type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS user_notification_preferences (
                user_id BIGINT PRIMARY KEY,
                security_alerts INTEGER NOT NULL DEFAULT 1,
                earning_alerts INTEGER NOT NULL DEFAULT 1,
                transaction_alerts INTEGER NOT NULL DEFAULT 1,
                account_alerts INTEGER NOT NULL DEFAULT 1,
                push_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS user_push_subscriptions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                endpoint TEXT UNIQUE NOT NULL,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        db.execute("""
            ALTER TABLE user_sessions
            ADD COLUMN IF NOT EXISTS device_name TEXT
        """)

        db.execute("""
            ALTER TABLE user_sessions
            ADD COLUMN IF NOT EXISTS user_agent TEXT
        """)

        db.execute("""
            ALTER TABLE user_sessions
            ADD COLUMN IF NOT EXISTS ip_address TEXT
        """)

        db.commit()
    finally:
        db.close()


ensure_user_security_tables()


def current_user_from_request():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None

    token = auth[7:].strip()
    if not token:
        return None, None

    db = get_db()
    try:
        row = db.execute("""
            SELECT
                s.id AS session_id,
                s.user_id,
                s.token,
                u.id,
                u.name,
                u.email,
                u.balance,
                u.currency,
                u.account_id,
                u.avatar_url
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
              AND s.expires_at > CURRENT_TIMESTAMP
            LIMIT 1
        """, (token,)).fetchone()

        if not row:
            return None, None

        db.execute("""
            UPDATE user_sessions
            SET last_used_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (row["session_id"],))
        db.commit()

        return dict(row), token
    finally:
        db.close()


def log_user_security_event(
    user_id,
    event_type,
    title,
    message,
    metadata=None,
    create_notification=True
):
    db = get_db()
    try:
        db.execute("""
            INSERT INTO user_security_events
            (user_id, event_type, title, message, metadata)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            event_type,
            title,
            message,
            json.dumps(metadata or {})
        ))

        if create_notification:
            db.execute("""
                INSERT INTO notifications
                (user_id, title, message)
                VALUES (?, ?, ?)
            """, (
                user_id,
                title,
                message
            ))

        db.commit()
    finally:
        db.close()


def send_user_push_notifications(user_id, title, message, data=None):
    """
    Sends Web Push notifications when VAPID credentials are configured.
    Push failures never break the main financial/security transaction.
    """
    try:
        from pywebpush import webpush, WebPushException
    except Exception:
        return

    vapid_private_key = os.environ.get("VAPID_PRIVATE_KEY", "").strip()
    vapid_subject = os.environ.get(
        "VAPID_SUBJECT",
        "mailto:admin@vicky-earn.com"
    ).strip()

    if not vapid_private_key:
        return

    db = get_db()
    try:
        subscriptions = db.execute("""
            SELECT id, endpoint, p256dh, auth
            FROM user_push_subscriptions
            WHERE user_id = ?
        """, (user_id,)).fetchall()

        for sub in subscriptions:
            subscription_info = {
                "endpoint": sub["endpoint"],
                "keys": {
                    "p256dh": sub["p256dh"],
                    "auth": sub["auth"],
                }
            }

            payload = json.dumps({
                "title": title,
                "body": message,
                "data": data or {}
            })

            try:
                webpush(
                    subscription_info=subscription_info,
                    data=payload,
                    vapid_private_key=vapid_private_key,
                    vapid_claims={"sub": vapid_subject},
                )

                db.execute("""
                    UPDATE user_push_subscriptions
                    SET last_used_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (sub["id"],))

            except Exception:
                # Invalid subscriptions are removed.
                try:
                    db.execute("""
                        DELETE FROM user_push_subscriptions
                        WHERE id = ?
                    """, (sub["id"],))
                except Exception:
                    pass

        db.commit()
    except Exception:
        db.rollback()
        app.logger.exception("Push notification delivery failed")
    finally:
        db.close()


def notify_user(
    user_id,
    title,
    message,
    event_type="general",
    metadata=None,
    push=True
):
    try:
        log_user_security_event(
            user_id,
            event_type,
            title,
            message,
            metadata,
            create_notification=True
        )
    except Exception:
        app.logger.exception("User notification creation failed")

    if push:
        try:
            send_user_push_notifications(
                user_id,
                title,
                message,
                metadata
            )
        except Exception:
            app.logger.exception("User push notification failed")


# ============================================================
# USER SETTINGS / SECURITY API
# ============================================================

@app.get("/api/settings")
def get_user_settings():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    db = get_db()
    try:
        preferences = db.execute("""
            SELECT
                security_alerts,
                earning_alerts,
                transaction_alerts,
                account_alerts,
                push_enabled
            FROM user_notification_preferences
            WHERE user_id = ?
        """, (user["user_id"],)).fetchone()

        if not preferences:
            db.execute("""
                INSERT INTO user_notification_preferences
                (user_id)
                VALUES (?)
            """, (user["user_id"],))
            db.commit()

            preferences = db.execute("""
                SELECT
                    security_alerts,
                    earning_alerts,
                    transaction_alerts,
                    account_alerts,
                    push_enabled
                FROM user_notification_preferences
                WHERE user_id = ?
            """, (user["user_id"],)).fetchone()

        credentials = db.execute("""
            SELECT
                id,
                device_name,
                created_at,
                last_used_at
            FROM user_webauthn_credentials
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user["user_id"],)).fetchall()

        sessions = db.execute("""
            SELECT
                id,
                device_name,
                user_agent,
                created_at,
                last_used_at,
                expires_at,
                token
            FROM user_sessions
            WHERE user_id = ?
            ORDER BY last_used_at DESC
        """, (user["user_id"],)).fetchall()

        safe_sessions = []
        for row in sessions:
            item = dict(row)
            item.pop("token", None)
            item["current"] = row["token"] == token
            safe_sessions.append(item)

        return jsonify({
            "success": True,
            "user": user,
            "preferences": dict(preferences),
            "biometrics": [dict(row) for row in credentials],
            "sessions": safe_sessions
        })
    finally:
        db.close()


@app.post("/api/settings/password")
def change_user_password():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    data = request.get_json(silent=True) or {}

    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    if len(new_password) < 8:
        return jsonify({
            "success": False,
            "message": "New password must be at least 8 characters."
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "message": "New passwords do not match."
        }), 400

    db = get_db()
    try:
        stored = db.execute("""
            SELECT password
            FROM users
            WHERE id = ?
        """, (user["user_id"],)).fetchone()

        # Existing password is optional because normal Vicky Earn
        # login remains phone-security/WebAuthn based.
        if stored and stored["password"]:
            if current_password and not check_password_hash(
                stored["password"],
                current_password
            ):
                return jsonify({
                    "success": False,
                    "message": "Current password is incorrect."
                }), 400

        new_hash = generate_password_hash(new_password)

        db.execute("""
            UPDATE users
            SET password = ?
            WHERE id = ?
        """, (new_hash, user["user_id"]))

        db.commit()

        log_user_security_event(
            user["user_id"],
            "password_changed",
            "Account password was set or changed."
        )

        return jsonify({
            "success": True,
            "message": "Password saved successfully."
        })

    finally:
        db.close()

@app.post("/api/settings/preferences")
def update_user_preferences():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    data = request.get_json(silent=True) or {}

    fields = {
        "security_alerts": int(bool(data.get("security_alerts", True))),
        "earning_alerts": int(bool(data.get("earning_alerts", True))),
        "transaction_alerts": int(bool(data.get("transaction_alerts", True))),
        "account_alerts": int(bool(data.get("account_alerts", True))),
        "push_enabled": int(bool(data.get("push_enabled", False))),
    }

    db = get_db()
    try:
        db.execute("""
            INSERT INTO user_notification_preferences
            (user_id, security_alerts, earning_alerts,
             transaction_alerts, account_alerts, push_enabled,
             updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT (user_id)
            DO UPDATE SET
                security_alerts = EXCLUDED.security_alerts,
                earning_alerts = EXCLUDED.earning_alerts,
                transaction_alerts = EXCLUDED.transaction_alerts,
                account_alerts = EXCLUDED.account_alerts,
                push_enabled = EXCLUDED.push_enabled,
                updated_at = CURRENT_TIMESTAMP
        """, (
            user["user_id"],
            fields["security_alerts"],
            fields["earning_alerts"],
            fields["transaction_alerts"],
            fields["account_alerts"],
            fields["push_enabled"],
        ))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Notification preferences updated.",
            "preferences": fields
        })
    finally:
        db.close()


@app.get("/api/settings/security-events")
def get_security_events():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    db = get_db()
    try:
        rows = db.execute("""
            SELECT
                id,
                event_type,
                title,
                message,
                metadata,
                created_at
            FROM user_security_events
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 100
        """, (user["user_id"],)).fetchall()

        return jsonify({
            "success": True,
            "events": [dict(row) for row in rows]
        })
    finally:
        db.close()


@app.delete("/api/settings/biometrics/<int:credential_id>")
def delete_user_biometric(credential_id):
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    db = get_db()
    try:
        credential = db.execute("""
            SELECT id, device_name
            FROM user_webauthn_credentials
            WHERE id = ?
              AND user_id = ?
        """, (credential_id, user["user_id"])).fetchone()

        if not credential:
            return jsonify({
                "success": False,
                "message": "Biometric credential not found."
            }), 404

        db.execute("""
            DELETE FROM user_webauthn_credentials
            WHERE id = ?
              AND user_id = ?
        """, (credential_id, user["user_id"]))

        db.commit()

        notify_user(
            user["user_id"],
            "Phone security removed",
            "A phone security credential was removed from your Vicky Earn account.",
            "biometric_removed",
            {"credential_id": credential_id}
        )

        return jsonify({
            "success": True,
            "message": "Phone security credential removed."
        })
    finally:
        db.close()


@app.delete("/api/settings/sessions/<int:session_id>")
def revoke_user_session(session_id):
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    db = get_db()
    try:
        session = db.execute("""
            SELECT id, token
            FROM user_sessions
            WHERE id = ?
              AND user_id = ?
        """, (session_id, user["user_id"])).fetchone()

        if not session:
            return jsonify({
                "success": False,
                "message": "Session not found."
            }), 404

        if session["token"] == token:
            return jsonify({
                "success": False,
                "message": "The current device cannot be revoked here."
            }), 400

        db.execute("""
            DELETE FROM user_sessions
            WHERE id = ?
              AND user_id = ?
        """, (session_id, user["user_id"]))

        db.commit()

        notify_user(
            user["user_id"],
            "Device signed out",
            "Another Vicky Earn device session was signed out.",
            "device_signed_out",
            {"session_id": session_id}
        )

        return jsonify({
            "success": True,
            "message": "Device signed out successfully."
        })
    finally:
        db.close()


@app.post("/api/settings/sessions/revoke-others")
def revoke_other_user_sessions():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    db = get_db()
    try:
        cursor = db.execute("""
            DELETE FROM user_sessions
            WHERE user_id = ?
              AND token <> ?
        """, (user["user_id"], token))

        db.commit()

        notify_user(
            user["user_id"],
            "Other devices signed out",
            "All other Vicky Earn device sessions were signed out.",
            "devices_signed_out",
            {"count": cursor.rowcount}
        )

        return jsonify({
            "success": True,
            "message": "All other devices have been signed out.",
            "count": cursor.rowcount
        })
    finally:
        db.close()


@app.post("/api/settings/push/subscribe")
def save_push_subscription():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    data = request.get_json(silent=True) or {}
    subscription = data.get("subscription") or {}

    endpoint = str(subscription.get("endpoint", "")).strip()
    keys = subscription.get("keys") or {}
    p256dh = str(keys.get("p256dh", "")).strip()
    auth_key = str(keys.get("auth", "")).strip()

    if not endpoint or not p256dh or not auth_key:
        return jsonify({
            "success": False,
            "message": "Invalid push subscription."
        }), 400

    db = get_db()
    try:
        db.execute("""
            INSERT INTO user_push_subscriptions
            (user_id, endpoint, p256dh, auth)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (endpoint)
            DO UPDATE SET
                user_id = EXCLUDED.user_id,
                p256dh = EXCLUDED.p256dh,
                auth = EXCLUDED.auth,
                last_used_at = CURRENT_TIMESTAMP
        """, (
            user["user_id"],
            endpoint,
            p256dh,
            auth_key
        ))

        db.execute("""
            INSERT INTO user_notification_preferences
            (user_id, push_enabled)
            VALUES (?, 1)
            ON CONFLICT (user_id)
            DO UPDATE SET
                push_enabled = 1,
                updated_at = CURRENT_TIMESTAMP
        """, (user["user_id"],))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Phone notifications enabled."
        })
    finally:
        db.close()


@app.delete("/api/settings/push/subscribe")
def remove_push_subscription():
    user, token = current_user_from_request()

    if not user:
        return jsonify({
            "success": False,
            "message": "Authentication required"
        }), 401

    data = request.get_json(silent=True) or {}
    endpoint = str(data.get("endpoint", "")).strip()

    db = get_db()
    try:
        db.execute("""
            DELETE FROM user_push_subscriptions
            WHERE user_id = ?
              AND endpoint = ?
        """, (user["user_id"], endpoint))

        db.execute("""
            UPDATE user_notification_preferences
            SET push_enabled = 0,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        """, (user["user_id"],))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Phone notifications disabled."
        })
    finally:
        db.close()





# ============================================================
# WEBAUTHN / FINGERPRINT LOGIN
# ============================================================

def _webauthn_user_from_session():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None

    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None

    db = get_db()
    try:
        row = db.execute("""
            SELECT u.*
            FROM user_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = %s
              AND s.expires_at > CURRENT_TIMESTAMP
        """, (token,)).fetchone()
        return row
    finally:
        db.close()


def _webauthn_save_challenge(user_id, challenge, ceremony):
    db = get_db()
    try:
        db.execute("""
            DELETE FROM webauthn_challenges
            WHERE expires_at <= CURRENT_TIMESTAMP
               OR ceremony = %s
        """, (ceremony,))

        db.execute("""
            INSERT INTO webauthn_challenges
                (user_id, challenge, ceremony, expires_at)
            VALUES
                (%s, %s, %s, CURRENT_TIMESTAMP + INTERVAL '5 minutes')
        """, (user_id, challenge, ceremony))

        db.commit()
    finally:
        db.close()


def _webauthn_get_challenge(challenge, ceremony):
    db = get_db()
    try:
        row = db.execute("""
            SELECT *
            FROM webauthn_challenges
            WHERE challenge = %s
              AND ceremony = %s
              AND expires_at > CURRENT_TIMESTAMP
            LIMIT 1
        """, (challenge, ceremony)).fetchone()

        if row:
            db.execute(
                "DELETE FROM webauthn_challenges WHERE id = %s",
                (row["id"],)
            )
            db.commit()

        return row
    finally:
        db.close()


def _user_value(row, key, default=None):
    try:
        return row[key]
    except Exception:
        return default


@app.post("/api/auth/webauthn/register/options")
def webauthn_register_options():
    try:
        user = _webauthn_user_from_session()

        if not user:
            return jsonify({
                "success": False,
                "error": "Authentication required."
            }), 401

        db = get_db()
        try:
            existing = db.execute("""
                SELECT credential_id
                FROM user_webauthn_credentials
                WHERE user_id = %s
            """, (user["id"],)).fetchall()
        finally:
            db.close()

        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(row["credential_id"])
            )
            for row in existing
        ]

        user_handle = __import__("hashlib").sha256(
            f"vicky-webauthn-user:{user['id']}".encode()
        ).digest()

        options = generate_registration_options(
            rp_id=WEBAUTHN_RP_ID,
            rp_name=WEBAUTHN_RP_NAME,
            user_id=user_handle,
            user_name=str(
                _user_value(user, "email")
                or _user_value(user, "username")
                or user["id"]
            ),
            user_display_name=str(
                _user_value(user, "name")
                or _user_value(user, "full_name")
                or _user_value(user, "email")
                or user["id"]
            ),
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )

        challenge = bytes_to_base64url(options.challenge)

        _webauthn_save_challenge(
            user["id"],
            challenge,
            "registration"
        )

        return jsonify(json.loads(options_to_json(options)))

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"WebAuthn registration options failed: {exc}"
        }), 500


@app.post("/api/auth/webauthn/register/verify")
def webauthn_register_verify():
    user = _webauthn_user_from_session()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required."
        }), 401

    credential = request.get_json(silent=True) or {}
    client_data = credential.get("response", {})

    raw_id = credential.get("rawId")
    if not raw_id:
        return jsonify({
            "success": False,
            "error": "Missing credential ID."
        }), 400

    client_data_json = client_data.get("clientDataJSON")
    attestation_object = client_data.get("attestationObject")

    if not client_data_json or not attestation_object:
        return jsonify({
            "success": False,
            "error": "Invalid WebAuthn response."
        }), 400

    try:
        parsed_client = json.loads(
            base64url_to_bytes(client_data_json).decode("utf-8")
        )

        challenge = parsed_client.get("challenge")
        if not challenge:
            raise ValueError("Missing challenge.")

        stored = _webauthn_get_challenge(
            challenge,
            "registration"
        )

        if not stored or stored["user_id"] != user["id"]:
            return jsonify({
                "success": False,
                "error": "WebAuthn challenge expired or invalid."
            }), 400

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
        )

        credential_id = bytes_to_base64url(
            verification.credential_id
        )

        public_key = bytes_to_base64url(
            verification.credential_public_key
        )

        db = get_db()
        try:
            db.execute("""
                INSERT INTO user_webauthn_credentials
                    (user_id, credential_id, public_key, sign_count)
                VALUES
                    (%s, %s, %s, %s)
                ON CONFLICT (credential_id)
                DO UPDATE SET
                    public_key = EXCLUDED.public_key,
                    sign_count = EXCLUDED.sign_count,
                    last_used_at = CURRENT_TIMESTAMP
            """, (
                user["id"],
                credential_id,
                public_key,
                verification.sign_count,
            ))
            db.commit()
        finally:
            db.close()

        return jsonify({
            "success": True,
            "message": "Fingerprint login enabled."
        })

    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": f"Fingerprint registration failed: {exc}"
        }), 400


@app.post("/api/auth/webauthn/login/options")
def webauthn_login_options():
    try:
        options = generate_authentication_options(
            rp_id=WEBAUTHN_RP_ID,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        challenge = bytes_to_base64url(options.challenge)

        _webauthn_save_challenge(
            None,
            challenge,
            "authentication"
        )

        return jsonify(json.loads(options_to_json(options)))

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"WebAuthn login options failed: {exc}"
        }), 500


@app.post("/api/auth/webauthn/login/verify")
def webauthn_login_verify():
    credential = request.get_json(silent=True) or {}

    raw_id = credential.get("rawId")
    if not raw_id:
        return jsonify({
            "success": False,
            "error": "Missing credential ID."
        }), 400

    credential_id = bytes_to_base64url(
        base64url_to_bytes(raw_id)
    )

    db = get_db()
    try:
        stored_credential = db.execute("""
            SELECT *
            FROM user_webauthn_credentials
            WHERE credential_id = %s
            LIMIT 1
        """, (credential_id,)).fetchone()
    finally:
        db.close()

    if not stored_credential:
        return jsonify({
            "success": False,
            "error": "Fingerprint login is not registered on this device."
        }), 404

    client_data_json = (credential.get("response") or {}).get(
        "clientDataJSON"
    )

    if not client_data_json:
        return jsonify({
            "success": False,
            "error": "Invalid WebAuthn response."
        }), 400

    try:
        parsed_client = json.loads(
            base64url_to_bytes(client_data_json).decode("utf-8")
        )

        challenge = parsed_client.get("challenge")

        if not challenge:
            raise ValueError("Missing challenge.")

        stored_challenge = _webauthn_get_challenge(
            challenge,
            "authentication"
        )

        if not stored_challenge:
            return jsonify({
                "success": False,
                "error": "WebAuthn challenge expired or invalid."
            }), 400

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=WEBAUTHN_RP_ID,
            expected_origin=WEBAUTHN_ORIGIN,
            credential_public_key=base64url_to_bytes(
                stored_credential["public_key"]
            ),
            credential_current_sign_count=stored_credential["sign_count"],
            require_user_verification=True,
        )

        db = get_db()
        try:
            db.execute("""
                UPDATE user_webauthn_credentials
                SET sign_count = %s,
                    last_used_at = CURRENT_TIMESTAMP
                WHERE credential_id = %s
            """, (
                verification.new_sign_count,
                credential_id,
            ))
            db.commit()
        finally:
            db.close()

        session_token = create_user_session(
            stored_credential["user_id"]
        )

        db = get_db()
        try:
            user = db.execute("""
                SELECT *
                FROM users
                WHERE id = %s
                LIMIT 1
            """, (stored_credential["user_id"],)).fetchone()
        finally:
            db.close()

        if not user:
            return jsonify({
                "success": False,
                "error": "User account no longer exists."
            }), 404

        return jsonify({
            "success": True,
            "session_token": session_token,
            "user": dict(user),
        })

    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": f"Fingerprint login failed: {exc}"
        }), 401



# ============================================================
# ADMIN WEBAUTHN / FINGERPRINT LOGIN
# ============================================================

def ensure_admin_webauthn_table():
    db = get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_webauthn_credentials (
                id BIGSERIAL PRIMARY KEY,
                admin_id BIGINT NOT NULL,
                credential_id TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                sign_count BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.commit()
    finally:
        db.close()


ensure_admin_webauthn_table()


def _admin_from_session_token(token):
    if not token:
        return None

    db = get_db()
    try:
        row = db.execute("""
            SELECT a.*
            FROM admin_sessions s
            JOIN admins a ON a.id = s.admin_id
            WHERE s.token = %s
              AND s.expires_at > CURRENT_TIMESTAMP
            LIMIT 1
        """, (token,)).fetchone()
        return row
    finally:
        db.close()


def _admin_from_request():
    auth = request.headers.get("Authorization", "")

    if not auth.startswith("Bearer "):
        return None

    return _admin_from_session_token(
        auth.split(" ", 1)[1].strip()
    )


def _admin_webauthn_save_challenge(challenge, ceremony):
    db = get_db()
    try:
        db.execute("""
            DELETE FROM webauthn_challenges
            WHERE expires_at <= CURRENT_TIMESTAMP
               OR ceremony = %s
        """, (ceremony,))

        db.execute("""
            INSERT INTO webauthn_challenges
                (user_id, challenge, ceremony, expires_at)
            VALUES
                (NULL, %s, %s, CURRENT_TIMESTAMP + INTERVAL '5 minutes')
        """, (challenge, ceremony))

        db.commit()
    finally:
        db.close()




# TEMPORARY: remove all WebAuthn credentials for the authenticated admin.
@app.post("/api/admin/webauthn/reset-credentials")
def admin_webauthn_reset_credentials():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({
            "success": False,
            "message": "Admin authentication required"
        }), 401

    token = auth[7:].strip()
    admin = _admin_from_session_token(token)

    if not admin:
        return jsonify({
            "success": False,
            "message": "Invalid or expired admin session"
        }), 401

    db = get_db()
    try:
        admin_id = admin["id"] if "id" in admin.keys() else admin["admin_id"]

        result = db.execute(
            "DELETE FROM admin_webauthn_credentials WHERE admin_id = ?",
            (admin_id,)
        )
        db.commit()

        return jsonify({
            "success": True,
            "message": "Existing admin fingerprint/passkey removed.",
            "removed": result.rowcount
        })
    finally:
        db.close()

@app.post("/api/admin/webauthn/register/options")
def admin_webauthn_register_options():
    admin = _admin_from_request()

    if not admin:
        return jsonify({
            "success": False,
            "error": "Admin authentication required."
        }), 401

    try:
        db = get_db()
        try:
            existing = db.execute("""
                SELECT credential_id
                FROM admin_webauthn_credentials
                WHERE admin_id = %s
            """, (admin["id"],)).fetchall()
        finally:
            db.close()

        exclude_credentials = [
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(row["credential_id"])
            )
            for row in existing
        ]

        user_handle = __import__("hashlib").sha256(
            f"vicky-webauthn-admin:{admin['id']}".encode()
        ).digest()

        options = generate_registration_options(
            rp_id=ADMIN_WEBAUTHN_RP_ID,
            rp_name=ADMIN_WEBAUTHN_RP_NAME,
            user_id=user_handle,
            user_name=str(admin["email"]),
            user_display_name=str(admin["name"]),
            exclude_credentials=exclude_credentials,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )

        challenge = bytes_to_base64url(options.challenge)

        _admin_webauthn_save_challenge(
            challenge,
            "admin_registration"
        )

        return jsonify(json.loads(options_to_json(options)))

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Admin fingerprint registration failed: {exc}"
        }), 500


@app.post("/api/admin/webauthn/register/verify")
def admin_webauthn_register_verify():
    admin = _admin_from_request()

    if not admin:
        return jsonify({
            "success": False,
            "error": "Admin authentication required."
        }), 401

    credential = request.get_json(silent=True) or {}
    client_data = credential.get("response", {})

    client_data_json = client_data.get("clientDataJSON")
    attestation_object = client_data.get("attestationObject")

    if not client_data_json or not attestation_object:
        return jsonify({
            "success": False,
            "error": "Invalid WebAuthn response."
        }), 400

    try:
        parsed_client = json.loads(
            base64url_to_bytes(client_data_json).decode("utf-8")
        )

        challenge = parsed_client.get("challenge")

        if not challenge:
            raise ValueError("Missing challenge.")

        stored = _webauthn_get_challenge(
            challenge,
            "admin_registration"
        )

        if not stored:
            return jsonify({
                "success": False,
                "error": "WebAuthn challenge expired or invalid."
            }), 400

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=ADMIN_WEBAUTHN_RP_ID,
            expected_origin=ADMIN_WEBAUTHN_ORIGIN,
        )

        credential_id = bytes_to_base64url(
            verification.credential_id
        )

        public_key = bytes_to_base64url(
            verification.credential_public_key
        )

        db = get_db()
        try:
            db.execute("""
                INSERT INTO admin_webauthn_credentials
                    (admin_id, credential_id, public_key, sign_count)
                VALUES
                    (%s, %s, %s, %s)
                ON CONFLICT (credential_id)
                DO UPDATE SET
                    admin_id = EXCLUDED.admin_id,
                    public_key = EXCLUDED.public_key,
                    sign_count = EXCLUDED.sign_count,
                    last_used_at = CURRENT_TIMESTAMP
            """, (
                admin["id"],
                credential_id,
                public_key,
                verification.sign_count,
            ))
            db.commit()
        finally:
            db.close()

        return jsonify({
            "success": True,
            "message": "Admin fingerprint login enabled."
        })

    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": f"Admin fingerprint registration failed: {exc}"
        }), 400


@app.post("/api/admin/webauthn/login/options")
def admin_webauthn_login_options():
    try:
        options = generate_authentication_options(
            rp_id=ADMIN_WEBAUTHN_RP_ID,
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        challenge = bytes_to_base64url(options.challenge)

        _admin_webauthn_save_challenge(
            challenge,
            "admin_authentication"
        )

        return jsonify(json.loads(options_to_json(options)))

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"Admin fingerprint login options failed: {exc}"
        }), 500


@app.post("/api/admin/webauthn/login/verify")
def admin_webauthn_login_verify():
    credential = request.get_json(silent=True) or {}

    raw_id = credential.get("rawId")

    if not raw_id:
        return jsonify({
            "success": False,
            "error": "Missing credential ID."
        }), 400

    credential_id = bytes_to_base64url(
        base64url_to_bytes(raw_id)
    )

    db = get_db()
    try:
        stored = db.execute("""
            SELECT *
            FROM admin_webauthn_credentials
            WHERE credential_id = %s
            LIMIT 1
        """, (credential_id,)).fetchone()
    finally:
        db.close()

    if not stored:
        return jsonify({
            "success": False,
            "error": "Admin fingerprint is not registered on this device."
        }), 404

    client_data_json = (credential.get("response") or {}).get(
        "clientDataJSON"
    )

    if not client_data_json:
        return jsonify({
            "success": False,
            "error": "Invalid WebAuthn response."
        }), 400

    try:
        parsed_client = json.loads(
            base64url_to_bytes(client_data_json).decode("utf-8")
        )

        challenge = parsed_client.get("challenge")

        if not challenge:
            raise ValueError("Missing challenge.")

        stored_challenge = _webauthn_get_challenge(
            challenge,
            "admin_authentication"
        )

        if not stored_challenge:
            return jsonify({
                "success": False,
                "error": "WebAuthn challenge expired or invalid."
            }), 400

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(challenge),
            expected_rp_id=ADMIN_WEBAUTHN_RP_ID,
            expected_origin=ADMIN_WEBAUTHN_ORIGIN,
            credential_public_key=base64url_to_bytes(
                stored["public_key"]
            ),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )

        db = get_db()

        try:
            db.execute("""
                UPDATE admin_webauthn_credentials
                SET sign_count = %s,
                    last_used_at = CURRENT_TIMESTAMP
                WHERE credential_id = %s
            """, (
                verification.new_sign_count,
                credential_id,
            ))

            db.commit()
        finally:
            db.close()

        session_token = secrets.token_urlsafe(64)

        db = get_db()

        try:
            db.execute("""
                INSERT INTO admin_sessions
                    (admin_id, token, expires_at)
                VALUES
                    (%s, %s, CURRENT_TIMESTAMP + INTERVAL '30 days')
            """, (
                stored["admin_id"],
                session_token,
            ))

            admin = db.execute("""
                SELECT id, name, email, avatar_url
                FROM admins
                WHERE id = %s
                LIMIT 1
            """, (stored["admin_id"],)).fetchone()

            db.commit()
        finally:
            db.close()

        if not admin:
            return jsonify({
                "success": False,
                "error": "Admin account no longer exists."
            }), 404

        return jsonify({
            "success": True,
            "token": session_token,
            "admin": dict(admin),
        })

    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        return jsonify({
            "success": False,
            "error": f"Admin fingerprint login failed: {exc}"
        }), 401


def ensure_env_admin():
    """
    Create or update the deployed admin account from environment variables.
    """
    import os
    from werkzeug.security import generate_password_hash

    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    name = os.environ.get("ADMIN_NAME", "").strip()
    password = os.environ.get("ADMIN_PASSWORD", "")

    if not email or not name or not password:
        app.logger.warning(
            "ADMIN_EMAIL, ADMIN_NAME or ADMIN_PASSWORD is missing."
        )
        return

    db = get_db()

    try:
        admin = db.execute(
            "SELECT id FROM admins WHERE email = ?",
            (email,)
        ).fetchone()

        password_hash = generate_password_hash(password)

        if admin:
            db.execute(
                """
                UPDATE admins
                SET name = ?, password = ?
                WHERE email = ?
                """,
                (name, password_hash, email)
            )
        else:
            db.execute(
                """
                INSERT INTO admins (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, password_hash)
            )

        db.commit()

        app.logger.info("✅ Environment admin account ready.")

    finally:
        db.close()


# Initialize the deployment admin when Flask/Gunicorn imports this module.
ensure_env_admin()


@app.get("/api/vickycoin/status")
def vickycoin_status():
    try:
        if not vic_enabled():
            return jsonify({
                "success": False,
                "enabled": False,
                "error": "VICKYCOIN_NODE_URL is not configured"
            }), 503

        data = vic_get_status()

        return jsonify({
            "success": True,
            "enabled": True,
            "network": data.get("network"),
            "nodeId": data.get("nodeId"),
            "height": data.get("height"),
            "blocks": data.get("blocks"),
            "peerCount": data.get("peerCount"),
            "mempool": data.get("mempool"),
            "supply": data.get("supply"),
            "maxSupply": data.get("maxSupply")
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "enabled": True,
            "error": str(e)
        }), 502


@app.get("/api/vickycoin/balance/<address>")
def vickycoin_balance(address):
    try:
        data = vic_get_balance(address)

        return jsonify({
            "success": True,
            "address": data.get("address"),
            "balance": data.get("balance"),
            "balanceVIC": data.get("balanceVIC"),
            "nonce": data.get("nonce")
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 502


@app.get("/api/vickycoin/transaction/<tx_id>")
def vickycoin_transaction(tx_id):
    try:
        data = vic_get_transaction(tx_id)
        return jsonify({
            "success": True,
            **data
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 502


if __name__ == "__main__":
    print("Vicky Earn API starting...")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )


# ============================================================
# PRODUCTION PAYMENT API
# ============================================================

from payments import (
    new_reference,
    paystack_initialize,
    paystack_verify,
    paystack_create_recipient,
    paystack_transfer,
    paystack_verify_transfer,
    flutterwave_verify_transaction,
    flutterwave_transfer,
    flutterwave_verify_transfer,
)


def payment_user(user_id):
    db = get_db()
    try:
        return db.execute(
            """
            SELECT id, name, email, balance, currency, account_id
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    finally:
        db.close()


@app.route("/api/payments/deposit", methods=["POST"])
def create_production_deposit():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    amount = data.get("amount")
    currency = str(data.get("currency", "NGN")).upper()
    callback_url = data.get(
        "callback_url",
        "https://vicky-earn-frontend.vercel.app/"
    )

    if not user_id or not amount:
        return jsonify({
            "success": False,
            "message": "User ID and amount are required"
        }), 400

    try:
        amount = float(amount)
    except Exception:
        return jsonify({
            "success": False,
            "message": "Invalid amount"
        }), 400

    if amount <= 0:
        return jsonify({
            "success": False,
            "message": "Amount must be greater than zero"
        }), 400

    user = payment_user(user_id)

    if not user:
        return jsonify({
            "success": False,
            "message": "User not found"
        }), 404

    reference = new_reference("DEP")

    try:
        if currency in ("NGN", "GHS"):
            result = paystack_initialize(
                user["email"],
                amount,
                currency,
                reference,
                callback_url,
                user_id,
            )

            if not result.get("status"):
                return jsonify({
                    "success": False,
                    "message": result.get("message", "Payment initialization failed")
                }), 400

            db = get_db()

            try:
                db.execute(
                    """
                    INSERT INTO transactions
                    (user_id, type, amount, currency, description, created_at)
                    VALUES (?, 'deposit_pending', ?, ?, ?, CURRENT_TIMESTAMP)
                    """,
                    (
                        user_id,
                        amount,
                        currency,
                        f"Provider deposit {reference}",
                    ),
                )
                db.commit()
            finally:
                db.close()

            return jsonify({
                "success": True,
                "status": "pending",
                "provider": "paystack",
                "reference": reference,
                "authorization_url":
                    result["data"]["authorization_url"],
            })

        return jsonify({
            "success": False,
            "message": (
                "This deposit currency requires its configured "
                "regional provider."
            )
        }), 400

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 502


@app.route("/api/payments/deposit/verify", methods=["POST"])
def verify_production_deposit():
    data = request.get_json(silent=True) or {}

    reference = str(data.get("reference", "")).strip()

    if not reference:
        return jsonify({
            "success": False,
            "message": "Payment reference is required"
        }), 400

    try:
        result = paystack_verify(reference)

        if not result.get("status"):
            return jsonify({
                "success": False,
                "message": "Provider verification failed"
            }), 400

        payment = result.get("data") or {}

        if payment.get("status") != "success":
            return jsonify({
                "success": False,
                "message": "Payment has not been completed"
            }), 409

        metadata = payment.get("metadata") or {}
        user_id = metadata.get("user_id")

        if not user_id:
            user_id = data.get("user_id")

        if not user_id:
            return jsonify({
                "success": False,
                "message": "Payment is missing user association"
            }), 400

        amount = Decimal(str(payment.get("amount", 0))) / Decimal("100")
        currency = str(payment.get("currency", "NGN")).upper()

        with transaction() as db:

            existing = db.execute(
                """
                SELECT id
                FROM transactions
                WHERE description = ?
                LIMIT 1
                """,
                (f"Provider deposit {reference}",),
            ).fetchone()

            if existing:
                return jsonify({
                    "success": True,
                    "message": "Payment already credited",
                    "reference": reference,
                })

            user = db.execute(
                """
                SELECT id, balance
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()

            if not user:
                return jsonify({
                    "success": False,
                    "message": "User not found"
                }), 404

            db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (amount, user_id),
            )

            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, currency, description, created_at)
                VALUES (?, 'deposit', ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    amount,
                    currency,
                    f"Verified provider deposit {reference}",
                ),
            )

        return jsonify({
            "success": True,
            "message": "Deposit verified and credited",
            "reference": reference,
            "amount": float(amount),
            "currency": currency,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 502


@app.route("/api/payments/withdraw", methods=["POST"])
def production_withdraw():
    data = request.get_json(silent=True) or {}

    user_id = data.get("user_id")
    amount = data.get("amount")
    currency = str(data.get("currency", "NGN")).upper()
    method = str(data.get("method", "bank")).lower()
    account_number = str(data.get("account_number", "")).strip()
    bank_code = str(data.get("bank_code", "")).strip()
    beneficiary_name = str(
        data.get("beneficiary_name", "")
    ).strip()

    if not user_id or not amount:
        return jsonify({
            "success": False,
            "message": "User ID and amount are required"
        }), 400

    if not account_number or not beneficiary_name:
        return jsonify({
            "success": False,
            "message": "Beneficiary details are required"
        }), 400

    try:
        amount = Decimal(str(amount))
    except Exception:
        return jsonify({
            "success": False,
            "message": "Invalid amount"
        }), 400

    if amount <= 0:
        return jsonify({
            "success": False,
            "message": "Amount must be greater than zero"
        }), 400

    reference = new_reference("WDR")

    with transaction() as db:
        user = db.execute(
            """
            SELECT id, balance, currency
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()

        if not user:
            return jsonify({
                "success": False,
                "message": "User not found"
            }), 404

        if Decimal(str(user["balance"])) < amount:
            return jsonify({
                "success": False,
                "message": "Insufficient balance"
            }), 400

        db.execute(
            """
            UPDATE users
            SET balance = balance - ?
            WHERE id = ?
            """,
            (amount, user_id),
        )

        db.execute(
            """
            INSERT INTO withdrawals
            (user_id, amount, currency, method, account, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'processing', CURRENT_TIMESTAMP)
            """,
            (
                user_id,
                amount,
                currency,
                method,
                account_number,
            ),
        )

    try:
        if currency == "NGN":
            recipient = paystack_create_recipient(
                beneficiary_name,
                account_number,
                bank_code,
                currency,
            )

            recipient_code = recipient["data"]["recipient_code"]

            transfer = paystack_transfer(
                recipient_code,
                amount,
                currency,
                reference,
            )

            return jsonify({
                "success": True,
                "status": "processing",
                "provider": "paystack",
                "reference": reference,
                "provider_response": transfer.get("data"),
            })

        if currency == "GHS":
            return jsonify({
                "success": False,
                "message": (
                    "GHS payout requires a configured Flutterwave "
                    "payout account."
                )
            }), 400

        if currency == "XOF":
            transfer = flutterwave_transfer(
                data.get("bank_code", ""),
                account_number,
                float(amount),
                currency,
                reference,
                beneficiary_name,
            )

            return jsonify({
                "success": True,
                "status": "processing",
                "provider": "flutterwave",
                "reference": reference,
                "provider_response": transfer.get("data"),
            })

        return jsonify({
            "success": False,
            "message": "No production payout provider configured for this currency"
        }), 400

    except Exception as exc:
        with transaction() as db:
            db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (amount, user_id),
            )

            db.execute(
                """
                UPDATE withdrawals
                SET status = 'failed'
                WHERE user_id = ?
                  AND status = 'processing'
                  AND amount = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (user_id, amount),
            )

        return jsonify({
            "success": False,
            "message": str(exc)
        }), 502


@app.route("/api/payments/webhook/paystack", methods=["POST"])
def paystack_webhook():
    payload = request.get_json(silent=True) or {}

    event = payload.get("event")
    payment = payload.get("data") or {}

    if event != "charge.success":
        return jsonify({"success": True})

    reference = payment.get("reference")

    if not reference:
        return jsonify({"success": True})

    try:
        result = paystack_verify(reference)

        if not result.get("status"):
            return jsonify({"success": True})

        verified = result.get("data") or {}

        if verified.get("status") != "success":
            return jsonify({"success": True})

        metadata = verified.get("metadata") or {}
        user_id = metadata.get("user_id")

        if not user_id:
            return jsonify({"success": True})

        amount = Decimal(
            str(verified.get("amount", 0))
        ) / Decimal("100")

        currency = str(
            verified.get("currency", "NGN")
        ).upper()

        with transaction() as db:

            duplicate = db.execute(
                """
                SELECT id
                FROM transactions
                WHERE description = ?
                LIMIT 1
                """,
                (f"Verified provider deposit {reference}",),
            ).fetchone()

            if duplicate:
                return jsonify({"success": True})

            db.execute(
                """
                UPDATE users
                SET balance = balance + ?
                WHERE id = ?
                """,
                (amount, user_id),
            )

            db.execute(
                """
                INSERT INTO transactions
                (user_id, type, amount, currency, description, created_at)
                VALUES (?, 'deposit', ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (
                    user_id,
                    amount,
                    currency,
                    f"Verified provider deposit {reference}",
                ),
            )

        return jsonify({"success": True})

    except Exception:
        return jsonify({"success": True})


@app.route("/api/payments/health", methods=["GET"])
def production_payment_health():
    return jsonify({
        "success": True,
        "payments": {
            "paystack": bool(os.getenv("PAYSTACK_SECRET_KEY")),
            "flutterwave": bool(os.getenv("FLW_SECRET_KEY")),
            "mode": os.getenv("PAYMENT_MODE", "production"),
        },
    })


# ============================================================
# VICKY EARN PROFIT API
# ============================================================

@app.route("/api/admin/profit", methods=["GET"])
@admin_required
def admin_profit_summary():
    db = get_db()
    try:
        revenue = db.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM platform_revenue
        """).fetchone()[0] or 0

        expenses = db.execute("""
            SELECT COALESCE(SUM(amount), 0)
            FROM platform_expenses
        """).fetchone()[0] or 0

        net_profit = float(revenue) - float(expenses)

        revenue_rows = db.execute("""
            SELECT id, type, amount, currency, description, created_at
            FROM platform_revenue
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

        expense_rows = db.execute("""
            SELECT id, type, amount, currency, description, created_at
            FROM platform_expenses
            ORDER BY id DESC
            LIMIT 50
        """).fetchall()

        return jsonify({
            "success": True,
            "profit": {
                "revenue": float(revenue),
                "expenses": float(expenses),
                "net_profit": net_profit
            },
            "revenue_records": [dict(row) for row in revenue_rows],
            "expense_records": [dict(row) for row in expense_rows]
        })
    finally:
        db.close()


@app.route("/api/admin/profit/revenue", methods=["POST"])
@admin_required
def admin_add_profit_revenue():
    data = request.get_json(silent=True) or {}

    revenue_type = str(data.get("type", "")).strip()
    description = str(data.get("description", "")).strip()
    currency = str(data.get("currency", "NGN")).strip().upper()

    if not revenue_type:
        return jsonify({
            "success": False,
            "message": "Revenue type is required."
        }), 400

    try:
        amount = parse_amount(data.get("amount"))
    except Exception:
        return jsonify({
            "success": False,
            "message": "Invalid revenue amount."
        }), 400

    if amount <= 0:
        return jsonify({
            "success": False,
            "message": "Revenue amount must be greater than zero."
        }), 400

    db = get_db()
    try:
        cursor = db.execute("""
            INSERT INTO platform_revenue
            (type, amount, currency, description)
            VALUES (?, ?, ?, ?)
        """, (
            revenue_type,
            amount,
            currency,
            description
        ))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Revenue recorded.",
            "id": cursor.lastrowid,
            "amount": float(amount),
            "currency": currency
        }), 201
    finally:
        db.close()


@app.route("/api/admin/profit/expense", methods=["POST"])
@admin_required
def admin_add_profit_expense():
    data = request.get_json(silent=True) or {}

    expense_type = str(data.get("type", "")).strip()
    description = str(data.get("description", "")).strip()
    currency = str(data.get("currency", "NGN")).strip().upper()

    if not expense_type:
        return jsonify({
            "success": False,
            "message": "Expense type is required."
        }), 400

    try:
        amount = parse_amount(data.get("amount"))
    except Exception:
        return jsonify({
            "success": False,
            "message": "Invalid expense amount."
        }), 400

    if amount <= 0:
        return jsonify({
            "success": False,
            "message": "Expense amount must be greater than zero."
        }), 400

    db = get_db()
    try:
        cursor = db.execute("""
            INSERT INTO platform_expenses
            (type, amount, currency, description)
            VALUES (?, ?, ?, ?)
        """, (
            expense_type,
            amount,
            currency,
            description
        ))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Expense recorded.",
            "id": cursor.lastrowid,
            "amount": float(amount),
            "currency": currency
        }), 201
    finally:
        db.close()
