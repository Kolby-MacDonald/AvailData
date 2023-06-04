import os
import socket
import threading
import pandas as pd
import mysql.connector
from datetime import datetime
from Crypto.Cipher import AES
from dotenv import load_dotenv


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
    
    try:
        results = cursor.fetchone()
        user_id = results[0]
        user_name = results[1]
        user_pass = results[2]
        user_table_access = results[3]
    except:
        pass

    if results:
        c.send("True".encode())
        print(f"{user_name} has accessed the database.")
        data_response(c, cursor, user_name, user_pass, user_table_access)
    else:
        c.send("False".encode())
        print(f"{credentials[0].decode()} has failed to access the database.")

    

def data_response(c, cursor, user_name, user_pass, user_table_access):
    cursor.execute(f'''SHOW TABLES''')
    database_table_names = cursor.fetchall()
    if user_table_access == "all":
        user_table_response = database_table_names
    else:
        apparent_table_names = user_table_access.split(',', 1)
        for item in apparent_table_names:
            if item not in database_table_names:
                apparent_table_names.remove(item)
        user_table_response = apparent_table_names
    
    print(user_table_response)
    cursor.execute(f'''SELECT * FROM {os.getenv("db_table_name")}''')
    df = pd.DataFrame(cursor.fetchall())
    #df = df.applymap(str)
    df = df.astype(str)
    print(df)
    c.send(f"{df}".encode())


    
    
    # key_aes = user_name
    # nonce_aes = user_pass

    # cipher_aes = AES.new(key_aes, AES.MODE_EAX, nonce_aes)


    

       

def main():
    load_dotenv()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    server_socket.listen()
    print("Server listening.")

    while True:
        client, addr = server_socket.accept()
        print(f"incoming connection by: {addr}")
        threading.Thread(target=handle_connection, args=(client,)).start()


main()
