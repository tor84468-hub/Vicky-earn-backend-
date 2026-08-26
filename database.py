import os
import sqlite3

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "vicky_earn.db"
)


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def column_exists(db, table, column):
    rows = db.execute(f"PRAGMA table_info({table})").fetchall()
    return any(row["name"] == column for row in rows)


def add_column_if_missing(db, table, column, definition):
    if not column_exists(db, table, column):
        db.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    db = get_db()

    # Main users table
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
        db, "users", "currency",
        "TEXT NOT NULL DEFAULT 'NGN'"
    )

    add_column_if_missing(
        db, "users", "account_id",
        "TEXT"
    )

    # Transactions
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
        db, "transactions", "currency",
        "TEXT NOT NULL DEFAULT 'NGN'"
    )

    # Earning tasks
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

    # Notifications
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

    # Withdrawals
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

    # Referrals
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

    # Give existing users Account IDs if they don't have one.
    users = db.execute("""
        SELECT id
        FROM users
        WHERE account_id IS NULL OR account_id = ''
    """).fetchall()

    import secrets

    for user in users:
        while True:
            account_id = "VKY-" + secrets.token_hex(3).upper()
            exists = db.execute(
                "SELECT id FROM users WHERE account_id = ?",
                (account_id,)
            ).fetchone()

            if not exists:
                break

        db.execute(
            "UPDATE users SET account_id = ? WHERE id = ?",
            (account_id, user["id"])
        )

    # Seed useful earning tasks if none exist.
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
    db.close()


if __name__ == "__main__":
    init_db()
    print("Vicky Earn database initialized successfully.")
