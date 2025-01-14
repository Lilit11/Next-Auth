const Database = require("better-sqlite3")
const authDB = new Database("auth.db")


authDB.exec(`
    CREATE TABLE IF NOT EXISTS users(
        id TEXT PRIMARY KEY,
        name TEXT,
        surname TEXT,
        login TEXT,
        password TEXT
    )
`)
// authDB.exec("DROP TABLE IF EXISTS users")
authDB.exec(`
    CREATE TABLE IF NOT EXISTS session (
    id TEXT NOT NULL PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    user_id TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES user(id)
)`
)
