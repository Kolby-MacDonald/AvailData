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
    
    try:
        results = cursor.fetchone()
        user_id = results[0]
        user_name = results[1]
        user_pass = results[2]
        user_table_access = results[3]
        print(f'user_id = {user_id}')
        print(f'user_name = {user_name}')
        print(f'user_table_access = {user_table_access}')
        print("Inputed username = " + credentials[0].decode())
    except:
        pass

    if results:
        c.send("True".encode())
        print(f"{user_name} has accessed the database.")
        handle_requests(c)
    else:
        c.send("False".encode())
        print(f"{credentials[0].decode()} has failed to access the database.")

    

def handle_requests(c):
    #Structure of requests:
    #str(list(
    # 0: request type
    # 1: parameters list ()
    # ))

    #Structure of response is dependant on request

    request_type = c.recv(1024)

    if request_type[0] == "update_available_tables":
        #get available tables from user table

        #if not = "all" then return a string of specific tables

    

        #format into a list

        #
        pass
    elif request_type[0] == "update_results_selection":
        
        pass

       

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
