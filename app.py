import os
import sqlite3
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

from database import init_db, get_db, transaction, generate_account_id

app = Flask(__name__)
CORS(app)

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
    password = str(data.get("password", ""))

    if not name or not email or not password:
        return jsonify({
            "success": False,
            "message": "Name, email and password are required"
        }), 400

    if len(password) < 6:
        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters"
        }), 400

    password_hash = generate_password_hash(password)

    try:
        with transaction() as db:
            existing = db.execute(
                "SELECT id FROM users WHERE email = ?",
                (email,)
            ).fetchone()

            if existing:
                return jsonify({
                    "success": False,
                    "message": "Email already registered"
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

        return jsonify({
            "success": True,
            "message": "Account created successfully",
            "user": {
                "id": user_id,
                "name": name,
                "email": email,
                "balance": 0,
                "account_id": account_id
            }
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Email or account ID already exists"
        }), 409


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email, password, balance, currency, account_id
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()
    finally:
        db.close()

    if not user or not check_password_hash(user["password"], password):
        return jsonify({
            "success": False,
            "message": "Invalid email or password"
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "balance": user["balance"],
            "currency": user["currency"],
            "account_id": user["account_id"]
        }
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
            SELECT id, name, email, balance, currency
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
# PROFILE
# ============================================================

@app.route("/api/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    db = get_db()

    try:
        user = db.execute(
            """
            SELECT id, name, email, balance, currency, created_at
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


if __name__ == "__main__":
    print("Vicky Earn API starting...")
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
