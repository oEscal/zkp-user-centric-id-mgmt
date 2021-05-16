import sqlite3


DB_NAME = 'idp.db'


def get_user(username):
    with sqlite3.connect(DB_NAME) as con:
        r = con.execute("SELECT password FROM user WHERE username=?",
                      [username])
        return r.fetchone()


def setup_database():
    with sqlite3.connect(DB_NAME) as con:
        con.execute("CREATE TABLE if not exists user ("
                    "username text primary key,"
                    "password text not null,"
                    "public_key text"
                    ")")
        con.execute("CREATE TABLE if not exists sessions ("
                    "token text primary key,"
                    "username text not null,"
                    "expiration_date text not null,"
                    "foreign key(username) references user(username)"
                    ")")
