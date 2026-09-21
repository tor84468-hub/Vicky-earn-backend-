import os
import re
import secrets
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row


DATABASE_URL = os.environ.get("DATABASE_URL")


if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable is required."
    )


class CursorCompat:
    """
    Small compatibility wrapper so the existing Vicky Earn app
    can continue using SQLite-style '?' parameters and
    cursor.lastrowid while the actual database is PostgreSQL.
    """

    def __init__(self, cursor):
        self.cursor = cursor
        self._lastrowid = None

    @property
    def rowcount(self):
        return self.cursor.rowcount

    @property
    def lastrowid(self):
        return self._lastrowid

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def __iter__(self):
        return iter(self.cursor)


class DBCompat:
    """
    PostgreSQL connection with compatibility for the existing
    SQLite-oriented Vicky Earn application.
    """

    def __init__(self, connection):
        self.connection = connection

    def _convert_sql(self, sql):
        # Existing app uses SQLite '?' parameters.
        sql = sql.replace("?", "%s")

        # SQLite date('now') -> PostgreSQL CURRENT_DATE
        sql = re.sub(
            r"date\(\s*'now'\s*\)",
            "CURRENT_DATE",
            sql,
            flags=re.IGNORECASE
        )

        # SQLite datetime('now') -> PostgreSQL CURRENT_TIMESTAMP
        sql = re.sub(
            r"datetime\(\s*'now'\s*\)",
            "CURRENT_TIMESTAMP",
            sql,
            flags=re.IGNORECASE
        )

        # SQLite datetime('now', '+7 days')
        sql = re.sub(
            r"datetime\(\s*'now'\s*,\s*'\+7 days'\s*\)",
            "(CURRENT_TIMESTAMP + INTERVAL '7 days')",
            sql,
            flags=re.IGNORECASE
        )

        return sql

    def execute(self, sql, params=()):
        converted = self._convert_sql(sql)

        # PostgreSQL does not provide SQLite's cursor.lastrowid.
        # For INSERT statements into our tables, automatically add
        # RETURNING id when possible so the existing app can continue
        # using cursor.lastrowid.
        stripped = converted.strip()

        is_insert = stripped.upper().startswith("INSERT INTO ")
        has_returning = " RETURNING " in stripped.upper()

        if is_insert and not has_returning:
            # Only add RETURNING id to INSERT statements that insert
            # into normal application tables.
            match = re.match(
                r"INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                stripped,
                flags=re.IGNORECASE
            )

            if match:
                table = match.group(1)

                if table not in {
                    "sqlite_sequence"
                }:
                    converted = converted.rstrip().rstrip(";")
                    converted += " RETURNING id"

                    cursor = self.connection.execute(
                        converted,
                        params
                    )

                    wrapper = CursorCompat(cursor)

                    row = cursor.fetchone()

                    if row and "id" in row:
                        wrapper._lastrowid = row["id"]

                    return wrapper

        cursor = self.connection.execute(
            converted,
            params
        )

        return CursorCompat(cursor)

    def executemany(self, sql, params_list):
        converted = self._convert_sql(sql)

        last_cursor = None
        for params in params_list:
            last_cursor = self.connection.execute(
                converted,
                params
            )

        return last_cursor

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def get_db():
    """
    Open a PostgreSQL database connection using Render's
    DATABASE_URL environment variable.
    """

    connection = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )

    return DBCompat(connection)


@contextmanager
def transaction():
    """
    Run database operations inside one atomic PostgreSQL transaction.
    """

    db = get_db()

    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def execute_with_retry(db, sql, params=(), retries=3):
    """
    PostgreSQL-compatible execute helper.

    Kept for compatibility with the existing application.
    """

    last_error = None

    for attempt in range(retries):
        try:
            return db.execute(sql, params)
        except psycopg.OperationalError as error:
            last_error = error

            if attempt == retries - 1:
                raise

    raise last_error


def column_exists(db, table, column):
    """
    Check whether a PostgreSQL table contains a column.
    """

    result = db.execute(
        """
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = %s
          AND column_name = %s
        LIMIT 1
        """,
        (table, column)
    ).fetchone()

    return result is not None


def add_column_if_missing(db, table, column, definition):
    if not column_exists(db, table, column):
        db.execute(
            f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}'
        )


def generate_account_id(db):
    """
    Generate a unique Vicky Earn account number.

    Format:
        VKY-XXXXXXXXXX
    """

    while True:
        account_id = "VKY-" + "".join(
            str(secrets.randbelow(10))
            for _ in range(10)
        )

        existing = db.execute(
            "SELECT id FROM users WHERE account_id = %s",
            (account_id,)
        ).fetchone()

        if not existing:
            return account_id


def init_db():
    db = get_db()

    try:
        # ========================================================
        # USERS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance DOUBLE PRECISION NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'NGN',
                account_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        add_column_if_missing(
            db,
            "users",
            "currency",
            "TEXT NOT NULL DEFAULT 'NGN'"
        )

        add_column_if_missing(
            db,
            "users",
            "account_id",
            "TEXT"
        )

        add_column_if_missing(
            db,
            "users",
            "phone",
            "TEXT"
        )

        add_column_if_missing(
            db,
            "users",
            "avatar_url",
            "TEXT"
        )

        # ========================================================
        # VICKY EARN — CUSTOMER FUNDING ACCOUNTS
        # ========================================================
        db.execute("""
            CREATE TABLE IF NOT EXISTS virtual_accounts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                provider TEXT NOT NULL,
                account_number TEXT NOT NULL,
                account_name TEXT,
                bank_name TEXT,
                provider_reference TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider, account_number),
                UNIQUE(provider, user_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_virtual_accounts_user
            ON virtual_accounts(user_id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_virtual_accounts_account
            ON virtual_accounts(provider, account_number)
        """)

        # ========================================================
        # PRODUCTION FINANCIAL LEDGER
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS wallet_accounts (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                currency TEXT NOT NULL,
                available_balance NUMERIC(24,8) NOT NULL DEFAULT 0,
                reserved_balance NUMERIC(24,8) NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, currency),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS ledger_transactions (
                id BIGSERIAL PRIMARY KEY,
                transaction_uuid TEXT UNIQUE NOT NULL,
                transaction_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'posted',
                reference TEXT UNIQUE,
                description TEXT,
                idempotency_key TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS ledger_entries (
                id BIGSERIAL PRIMARY KEY,
                ledger_transaction_id BIGINT NOT NULL,
                wallet_account_id BIGINT NOT NULL,
                entry_type TEXT NOT NULL,
                amount NUMERIC(24,8) NOT NULL,
                currency TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ledger_transaction_id)
                    REFERENCES ledger_transactions(id),
                FOREIGN KEY (wallet_account_id)
                    REFERENCES wallet_accounts(id),
                CHECK (amount > 0),
                CHECK (entry_type IN ('debit', 'credit'))
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS payment_transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                provider TEXT NOT NULL,
                provider_reference TEXT NOT NULL,
                transaction_type TEXT NOT NULL,
                amount NUMERIC(24,8) NOT NULL,
                currency TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                ledger_transaction_id BIGINT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(provider, provider_reference),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (ledger_transaction_id)
                    REFERENCES ledger_transactions(id)
            )
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_wallet_accounts_user
            ON wallet_accounts(user_id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_entries_wallet
            ON ledger_entries(wallet_account_id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ledger_entries_transaction
            ON ledger_entries(ledger_transaction_id)
        """)

        db.execute("""
            CREATE INDEX IF NOT EXISTS idx_payment_transactions_user
            ON payment_transactions(user_id)
        """)

        # ========================================================
        # MIGRATE EXISTING USER BALANCES INTO WALLET ACCOUNTS
        # ========================================================

        users_with_balances = db.execute("""
            SELECT id, currency, balance
            FROM users
            WHERE balance > 0
        """).fetchall()

        for user in users_with_balances:
            wallet = db.execute("""
                SELECT id
                FROM wallet_accounts
                WHERE user_id = ?
                  AND currency = ?
            """, (
                user["id"],
                str(user["currency"]).upper()
            )).fetchone()

            if not wallet:
                db.execute("""
                    INSERT INTO wallet_accounts
                    (
                        user_id,
                        currency,
                        available_balance
                    )
                    VALUES (?, ?, ?)
                """, (
                    user["id"],
                    str(user["currency"]).upper(),
                    user["balance"]
                ))

        # ========================================================
        # TRANSACTIONS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                type TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                description TEXT,
                currency TEXT NOT NULL DEFAULT 'NGN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        add_column_if_missing(
            db,
            "transactions",
            "currency",
            "TEXT NOT NULL DEFAULT 'NGN'"
        )

        # ========================================================
        # TASKS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id BIGSERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                reward DOUBLE PRECISION NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ========================================================
        # NOTIFICATIONS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # ========================================================
        # WITHDRAWALS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS withdrawals (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                method TEXT NOT NULL,
                account TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # ========================================================
        # WITHDRAWAL LEDGER / PROVIDER TRACKING
        # ========================================================

        add_column_if_missing(
            db,
            "withdrawals",
            "provider",
            "TEXT"
        )

        add_column_if_missing(
            db,
            "withdrawals",
            "provider_reference",
            "TEXT"
        )

        add_column_if_missing(
            db,
            "withdrawals",
            "ledger_transaction_id",
            "BIGINT"
        )

        add_column_if_missing(
            db,
            "withdrawals",
            "failure_reason",
            "TEXT"
        )

        # ========================================================
        # REFERRALS
        # ========================================================

        db.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                referred_user_id BIGINT,
                referral_code TEXT,
                reward DOUBLE PRECISION NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (referred_user_id) REFERENCES users(id)
            )
        """)

        # ========================================================
        # ADMIN TABLES
        # ========================================================

        add_column_if_missing(
            db,
            "admins",
            "avatar_url",
            "TEXT"
        )

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
                admin_id BIGINT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS platform_revenue (
                id BIGSERIAL PRIMARY KEY,
                type TEXT NOT NULL,
                amount DOUBLE PRECISION NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        db.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_logs (
                id BIGSERIAL PRIMARY KEY,
                admin_id BIGINT,
                action TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # ========================================================
        # ACCOUNT IDs
        # ========================================================

        users = db.execute("""
            SELECT id, account_id
            FROM users
            ORDER BY id
        """).fetchall()

        for user in users:
            current = str(
                user["account_id"] or ""
            ).strip().upper()

            valid = (
                len(current) == 14
                and current.startswith("VKY-")
                and current[4:].isdigit()
            )

            if valid:
                continue

            account_id = generate_account_id(db)

            db.execute(
                """
                UPDATE users
                SET account_id = %s
                WHERE id = %s
                """,
                (account_id, user["id"])
            )

        # ========================================================
        # SEED TASKS
        # ========================================================

        task_count = db.execute(
            "SELECT COUNT(*) AS count FROM tasks"
        ).fetchone()["count"]

        if task_count == 0:
            db.executemany("""
                INSERT INTO tasks
                (title, description, reward, active)
                VALUES (%s, %s, %s, 1)
            """, [
                (
                    "Daily check-in",
                    "Open Vicky Earn and complete your daily check-in.",
                    5
                ),
                (
                    "Complete your profile",
                    "Make sure your Vicky Earn profile is complete.",
                    5
                ),
                (
                    "Invite a friend",
                    "Invite a friend to join Vicky Earn.",
                    10
                )
            ])

        db.commit()

    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Vicky Earn PostgreSQL database initialized successfully.")
