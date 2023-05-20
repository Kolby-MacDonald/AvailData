import socket
import mysql.connector
import threading
from dotenv import load_dotenv
import os


def handle_connection(c):
    credentials = []
    while len(credentials) != 2:
        credentials.append(c.recv(1024))

    db = mysql.connector.connect(
        host=os.getenv("db_host"), 
        user=os.getenv("db_user"), 
        password=os.getenv("db_pass"),
        database=os.getenv("db_name")
        )
    
    cursor = db.cursor()
    print(f"{credentials[0].decode()} is attempting access to the database.")

    cursor.execute(
        f'''SELECT * FROM {os.getenv("db_table_name")} where username = %s and password = %s''',
        (credentials[0].decode(), credentials[1].decode())
        )

    if cursor.fetchall():
        c.send("True".encode())
        print(f"{credentials[0].decode()} has accessed the database.")
        #Services go here
    else:
        c.send("False".encode())
        print(f"{credentials[0].decode()} has failed to access the database.")


def env_configure():
    load_dotenv()


def main():
    env_configure()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    server_socket.listen()
    print("Server listening.")

    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(client,)).start()

main()
