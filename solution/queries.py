import sqlite3


DB_NAME = 'idp.db'


def get_user(username: str) -> tuple:
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT password FROM user WHERE username=?",
                      [username])
        return r.fetchone()


def save_user_key(id: str, username: str, key: str, not_valid_after: float) -> bool:
    try:
        with sqlite3.connect(DB_NAME) as con:
            con.execute("INSERT INTO keys(id, user, value, not_valid_after) values(?, ?, ?, ?)",
                        [id, username, key, not_valid_after])
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_user_key(id: str, username: str) -> tuple:
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT value, not_valid_after FROM keys WHERE id=? AND user=?", [id, username])
        return r.fetchone()


def setup_database():
    with sqlite3.connect(DB_NAME) as con:
        con.execute("CREATE TABLE if not exists user ("
                    "username text primary key,"
                    "password text not null"
                    ")")
        con.execute("CREATE TABLE if not exists keys ("
                    "id text primary key,"
                    "user text not null,"
                    "value text not null,"
                    "not_valid_after real not null,"
                    "foreign key(user) references user(username)"
                    ")")
        con.execute("CREATE TABLE if not exists sessions ("
                    "token text primary key,"
                    "username text not null,"
                    "expiration_date text not null,"
                    "foreign key(username) references user(username)"
                    ")")
