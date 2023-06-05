import os
import socket
import threading
import pandas as pd
import mysql.connector
from dotenv import load_dotenv


# Primary function controller.
def server_controller(server): 
    
    username = server.recv(1024)
    password = server.recv(1024)

    db = mysql.connector.connect(
        host=os.getenv("db_host"), 
        user=os.getenv("db_user"), 
        password=os.getenv("db_pass"),
        database=os.getenv("db_name")
        )
    
    cursor = db.cursor()
    print(f"{username.decode()} is attempting access to the database.")

    cursor.execute(
        f'''SELECT * FROM {os.getenv("db_table_name")} where username = %s and password = %s''',
        (username.decode(), password.decode())
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
        server.send("True".encode())
        print(f"{user_name} has accessed the database.")
        init_data_response(server, cursor, user_name, user_pass, user_table_access)
    else:
        server.send("False".encode())
        print(f"{username.decode()} has failed to access the database.")

    

def init_data_response(server, cursor, user_name, user_pass, user_table_access):
    cursor.execute(f'''SHOW TABLES''')
    database_table_names = cursor.fetchall()


    if user_table_access == "all":
        user_table_names = ''
        for i, tup in enumerate(database_table_names):
            user_table_names += tup[0] + ','
    else:
        try:
            apparent_table_names = user_table_access.split(', ')
            user_table_names = ''
            for i, tup in enumerate(database_table_names):
                if tup[0] in apparent_table_names:
                    user_table_names += tup[0] + ','
        except:
            user_table_names = ''

    if user_table_names != '':
        user_table_names = user_table_names[:-1]
        print(user_table_names)

        cursor.execute(f'''SELECT * FROM {os.getenv("db_table_name")}''')
        df = pd.DataFrame(cursor.fetchall())
        df = df.astype(str)
        print(df)

        #ENCRYPT DATA HERE

        server.send(f"{user_table_names}".encode())
        server.send(f"{df}".encode())
  

def main():
    load_dotenv()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    server_socket.listen()
    print("Server listening.")

    while True:
        server, addr = server_socket.accept()
        print(f"incoming connection by: {addr}")
        threading.Thread(target=server_controller, args=(server,)).start()

main()