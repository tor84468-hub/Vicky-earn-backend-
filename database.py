import os
import sqlite3
import secrets
import time

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vicky_earn.db"
)


def get_db():
    connection = sqlite3.connect(
        DATABASE,
        timeout=60,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    # SQLite reliability/concurrency settings.
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 60000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA synchronous = NORMAL")
    connection.execute("PRAGMA temp_store = MEMORY")

    return connection


def execute_with_retry(db, sql, params=(), retries=8):
    """
    Execute a database statement with retry handling for
    temporary SQLite locking.
    """
    for attempt in range(retries):
        try:
            return db.execute(sql, params)
        except sqlite3.OperationalError as error:
            if "database is locked" not in str(error).lower():
                raise

            if attempt == retries - 1:
                raise

            time.sleep(0.25 * (attempt + 1))


def column_exists(db, table, column):
    rows = db.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()

    return any(row["name"] == column for row in rows)


def add_column_if_missing(db, table, column, definition):
    if not column_exists(db, table, column):
        execute_with_retry(
            db,
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def generate_account_id(db):
    """
    Generate a unique Vicky Earn account number.

    Format:
        VKY-XXXXXXXXXX

    Example:
        VKY-4829173056
    """

    while True:
        account_id = "VKY-" + "".join(
            str(secrets.randbelow(10))
            for _ in range(10)
        )

        existing = db.execute(
            "SELECT id FROM users WHERE account_id = ?",
            (account_id,)
        ).fetchone()

        if not existing:
            return account_id


def init_db():
    db = get_db()

    try:
        # Main users table.
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance REAL NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'NGN',
                account_id TEXT UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Upgrade older databases safely.
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

        # Transactions.
        db.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
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

        # Earning tasks.
        db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                reward REAL NOT NULL DEFAULT 0,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Notifications.
        db.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                read INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Withdrawals.
        db.execute("""
            CREATE TABLE IF NOT EXISTS withdrawals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount REAL NOT NULL,
                currency TEXT NOT NULL DEFAULT 'NGN',
                method TEXT NOT NULL,
                account TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Referrals.
        db.execute("""
            CREATE TABLE IF NOT EXISTS referrals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                referred_user_id INTEGER,
                referral_code TEXT,
                reward REAL NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (referred_user_id) REFERENCES users(id)
            )
        """)

        # Ensure every user has a valid unique account number.
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

            execute_with_retry(
                db,
                """
                UPDATE users
                SET account_id = ?
                WHERE id = ?
                """,
                (account_id, user["id"])
            )

        # Seed earning tasks.
        task_count = db.execute(
            "SELECT COUNT(*) AS count FROM tasks"
        ).fetchone()["count"]

        if task_count == 0:
            db.executemany("""
                INSERT INTO tasks
                (title, description, reward, active)
                VALUES (?, ?, ?, 1)
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
    print("Vicky Earn database initialized successfully.")
