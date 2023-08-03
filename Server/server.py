import re
import os
import ssl
import json
import time
import math
import socket
import sqlite3
import threading
import pandas as pd
from OpenSSL import crypto
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from secrets import token_bytes


ACTIVE_THREADS = {}
TOTAL_CONNECTIONS = 0
LOCK = threading.Lock()

# Primary function controller.
def server_controller(client_sock, conn_ip, conn_num, thread_id):
    db = sqlite3.connect(f"database_container/{os.getenv('db_name')}")
    cursor = db.cursor()
    aes_key = key_exchange_handler(client_sock)
    credentials = receive_data(client_sock, aes_key, conn_num, thread_id, None, None, None, None, None, None, None, None, None)

    cursor.execute(
        f"SELECT * FROM {os.getenv('db_table_name')} WHERE username = ? AND password = ?",
        (str(credentials[1]), str(credentials[2]))
    )

    try:
        results = cursor.fetchone()
        user_db_id = results[0]
        employee_name = results[1]
        job_title = results[2]
        db_role = results[3]
        username = results[4]
        password = results[5]
        user_write_table_access = results[7]
        user_read_table_access = results[8]
        try:
            create_table_access = results[9].lower()
        except:
            create_table_access = "no"
    except: pass

    if results:
        send_data(client_sock, aes_key, True)
        print(f"{user_db_id} | {employee_name}:{username} | {job_title}:{db_role} | has accessed the database.")
        receive_data(client_sock, aes_key, conn_num, thread_id, db, cursor, db_role, user_write_table_access,
                      user_read_table_access, create_table_access, username, password, user_db_id)
    else:
        send_data(client_sock, aes_key, False)
        close_connection(client_sock, conn_num, thread_id, db)

######################################## KEY EXCHANGE ########################################################

def key_exchange_handler(client_sock):
    aes_key = token_bytes(128//8) 
    client_public_key = client_sock.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_key)
    encrypted_key = client_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
        )
    #SEND AES KEY
    client_sock.sendall(encrypted_key)
    return aes_key

######################################## SERVER RESPONSE FUNCTIONS ###################################################

def aes_encrypt(data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_json_data = pad(data.encode(), AES.block_size)
    enc_data = cipher.encrypt(padded_json_data)
    return enc_data

def aes_decrypt(enc_data, aes_key):
    cipher = AES.new(aes_key, AES.MODE_ECB)
    padded_enc_data = cipher.decrypt(enc_data)
    json_data = unpad(padded_enc_data, AES.block_size)
    return json_data.decode()

def send_data(client_sock, aes_key, data):
    json_data = json.dumps(data)
    enc_data = aes_encrypt(json_data, aes_key)
    data_length = len(enc_data)
    header = f"{data_length:<{15}}".encode('utf-8')
    chunk_size = 16380
    chunks = [enc_data[i:i+chunk_size] for i in range(0, data_length, chunk_size)]
    client_sock.sendall(header)
    for chunk in chunks:
        client_sock.sendall(chunk)

def receive_data(client_sock, aes_key, conn_num, thread_id, db, cursor, db_role, user_write_table_access, user_read_table_access, create_table_access, username, password, user_db_id):
    comm_time = int(time.time())
    timeout = 10
    while True:
        try:
            header = client_sock.recv(15)
            if not header:
                break

            data_length = int(header.strip())
            data = b""
            remaining_bytes = data_length

            while remaining_bytes > 0:
                chunk = client_sock.recv(remaining_bytes)
                if not chunk:
                    break
                data += chunk
                remaining_bytes -= len(chunk)
            
            comm_time = int(time.time())
            data = aes_decrypt(data, aes_key)
            json_data = json.loads(data)
            request_type = json_data[0]

            if request_type == "login":
                return json_data

            elif request_type == "get_init_data":
                user_table_names = init_data_response(client_sock, aes_key, cursor, db_role, user_read_table_access, create_table_access, username, password, user_db_id)
                user_write_table_names = user_table_names[0]
                user_read_table_names = user_table_names[1]

            elif request_type == "update_loaded_table":
                requested_table = json_data[1]
                result_select = json_data[2]
                page_select = json_data[3]
                update_loaded_table(client_sock, aes_key, cursor, user_write_table_names, user_read_table_names, requested_table, result_select, page_select)
            
            elif request_type == "update_database_row":
                table_to_update = json_data[1]
                update_data = json_data[2]
                update_database_row(client_sock, aes_key, cursor, table_to_update, update_data, user_write_table_names)
            
            elif request_type == "add_column":
                table_to_update = json_data[1]
                update_data = json_data[2]
                add_column(client_sock, aes_key, cursor, table_to_update, update_data, user_write_table_names)
            
            elif request_type == "delete_column":
                table_to_update = json_data[1]
                column_to_delete = json_data[2]
                delete_column(client_sock, aes_key, cursor, table_to_update, column_to_delete, user_write_table_names)
            
            elif request_type == "add_row":
                table_to_update = json_data[1]
                position_of_row = json_data[2]
                add_row(client_sock, aes_key, cursor, table_to_update, position_of_row, user_write_table_names)
            
            elif request_type == "delete_row":
                table_to_update = json_data[1]
                position_of_row = json_data[2]
                delete_row(client_sock, aes_key, cursor, table_to_update, position_of_row, user_write_table_names)
            
            elif request_type == "add_table":
                new_table_name = json_data[1]
                add_table(client_sock, aes_key, cursor, new_table_name, create_table_access, username, password, user_db_id, db_role)

            elif request_type == "log_out":
                close_connection(client_sock, conn_num, thread_id, db)
                break

            elif request_type == "delete_table":
                del_table_data = json_data[1]
                delete_table(client_sock, aes_key, cursor, del_table_data, user_write_table_names, password)
        except:
            pass
        
        current_time = int(time.time())
        if current_time - comm_time > timeout:
            close_connection(client_sock, conn_num, thread_id, db)
            break

######################################## DATA MANIPULATION FUNCTIONS ###################################################

def init_data_response(client_sock, aes_key, cursor, db_role, user_read_table_access, create_table_access, username, password, user_db_id):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    database_table_names_curse = cursor.fetchall()

    cursor.execute(f"SELECT write_access FROM {os.getenv('db_table_name')} WHERE username = ? AND password = ? and id = ?",(username, password, user_db_id))
    user_write_table_access = cursor.fetchone()[0]

    database_table_names = []
    user_write_table_names = []
    user_read_table_names = []

    for tables in database_table_names_curse:
        database_table_names.append(tables[0])

    untouchable_tables = ['sqlite_master', 'sqlite_sequence', 'sqlite_stat', 'sqlite_temp_master']
    database_table_names= [table for table in database_table_names if all(unt_table not in table for unt_table in untouchable_tables)]

    # Write control-------------------------------------------------------------------------------

    if user_write_table_access == "all" or db_role == "admin":
        user_write_table_names = database_table_names

    elif type(user_write_table_access) == type(''):
        apparent_table_names = user_write_table_access.split(', ')
        for table_name in apparent_table_names:
            if table_name in database_table_names and table_name not in user_write_table_names:
                user_write_table_names.append(str(table_name))

    # Read Control---------------------------------------------------------------------------

    if user_read_table_access == "all" and db_role != "admin":
        user_read_table_access == database_table_names

    elif type(user_read_table_access) == type(''):
        apparent_table_names = user_read_table_access.split(', ')
        for table_name in apparent_table_names:
            if table_name in database_table_names and table_name not in user_read_table_names and table_name not in user_write_table_names:
                user_read_table_names.append(str(table_name))

    data = [user_write_table_names, user_read_table_names, create_table_access]
    send_data(client_sock, aes_key, data)
    return user_write_table_names, user_read_table_names

def update_loaded_table(client_sock, aes_key, cursor, user_write_table_names, user_read_table_names, requested_table, result_select, page_select):
    column_names = []
    df = pd.DataFrame()
    user_table_names = user_read_table_names + user_write_table_names

    if requested_table != "":
        if len(user_table_names) >= 1 and requested_table in user_table_names:
            cursor.execute(f"PRAGMA table_info({requested_table})")
            columns = cursor.fetchall()

            cursor.execute(f"SELECT COUNT(1) FROM {requested_table};")
            total_rows = cursor.fetchone()[0]

            if total_rows == 0:
                total_pages = 1
            else:
                total_pages = abs(math.ceil(total_rows/int(result_select)))
                if int(page_select) > total_pages or int(page_select) <= 0:
                    page_select = 1
                    total_pages = 1

            for column in columns:
                column_names.append(column[1])
            if result_select.isdigit():
                cursor.execute(f'''SELECT * FROM {requested_table} LIMIT {int(result_select)} OFFSET {(int(page_select)-1)*int(result_select)}''')
            elif result_select.startswith("-") and result_select[1:].isdigit():
                cursor.execute(f'''SELECT * FROM {requested_table} LIMIT {abs(int(result_select))} OFFSET {(total_rows - abs(int(result_select))) + (int(page_select)-1)*int(result_select)}''')
            else:
                cursor.execute(f'''SELECT * FROM {requested_table} LIMIT 0''')
        
        df = pd.DataFrame(cursor.fetchall(), columns=column_names)
        df = df.to_dict()
        data = [df, page_select, total_pages]
    else: data = []
    send_data(client_sock, aes_key, data)

def update_database_row(client_sock, aes_key, cursor, table_to_update, update_data, user_write_table_names):
    if table_to_update not in user_write_table_names:
        send_data(client_sock, aes_key, False)
        return
    
    try:
        column_names_associated = update_data.pop()
        for data in update_data:
            old_row_data = data[1]
            new_row_data = data[2]

            set_clauses = ', '.join([f'{col} = ?' for col in column_names_associated])
            where_clauses = ' AND '.join([f'{col} IS ?' for col in column_names_associated])

            # Replace Python None with SQL NULL using the database adapter's placeholder
            update_values = tuple(new_row_data[i] if new_row_data[i] is not None else None for i in range(len(new_row_data))) + \
                            tuple(old_row_data[i] if old_row_data[i] is not None else None for i in range(len(old_row_data)))

            sql_query = f"UPDATE {table_to_update} SET {set_clauses} WHERE {where_clauses}"

            cursor.execute(sql_query, update_values)
            cursor.connection.commit()

        send_data(client_sock, aes_key, True)
    except:
        send_data(client_sock, aes_key, False)

def add_column(client_sock, aes_key, cursor, table_to_update, update_data, user_write_table_names):
    newcol_name = update_data[0]
    newcol_data_type = update_data[1]
    newcol_default_value = update_data[2]
    validation = False
    print(f"DEFAULT|{newcol_default_value}|")
    if table_to_update in user_write_table_names:
        try:
            if newcol_data_type in ["Text (All Characters)","Numbers (Integers & Decimals)","(In Beta) Blob (Images / Files)"]:
                if newcol_data_type == "Text (All Characters)":
                    newcol_data_type = "TEXT"
                elif newcol_data_type == "Numbers (Integers & Decimals)":
                    newcol_data_type = "NUMERIC"
                elif newcol_data_type == "(In Beta) Blob (Images / Files)":
                    newcol_data_type = "BLOB"
                
                if newcol_default_value == '' or newcol_default_value == None:
                    newcol_default_value = 'NULL'
                
                if re.match(r'^[a-zA-Z0-9_]+$', newcol_name) is not None:
                    if re.match(r'^[a-zA-Z0-9_]+$', newcol_default_value) is not None or re.match(r'^-?\d+(\.\d+)?$', newcol_default_value) is not None or newcol_default_value == 'NULL':
                        #Just incase the regular expression doesn't catch an escape string for some reason.
                        newcol_name = newcol_name.replace("'", "X")
                        newcol_name = newcol_name.replace('"', "X")
                        newcol_default_value = newcol_default_value.replace("'", "X")
                        newcol_default_value = newcol_default_value.replace('"', "X")
                        query = f"ALTER TABLE {table_to_update} ADD COLUMN '{newcol_name}' {newcol_data_type} DEFAULT {newcol_default_value};"
                        cursor.execute(query)
                        cursor.connection.commit()
                        validation = True
        except: pass
    send_data(client_sock, aes_key, validation)

def delete_column(client_sock, aes_key, cursor, table_to_update, column_to_delete, user_write_table_names):
    validation = False
    if table_to_update in user_write_table_names:
        try:
            cursor.execute(f"ALTER TABLE {table_to_update} DROP COLUMN {column_to_delete};")
            cursor.connection.commit()
            validation = True
        except Exception as e:
            print(e)
    send_data(client_sock, aes_key, validation)

def add_row(client_sock, aes_key, cursor, table_to_update, position_of_row, user_write_table_names):
    validation = False
    if table_to_update in user_write_table_names:
        try:
            try:
                cursor.execute(f"SELECT MAX(id) FROM {table_to_update}")
                max_id = cursor.fetchone()[0]
                cursor.execute(f"UPDATE {table_to_update} SET id = id + {max_id} + 1 WHERE id >= ?", (position_of_row,))
            except: pass
            cursor.execute(f"INSERT INTO {table_to_update} (id) VALUES (?)", (position_of_row,))
            try:
                cursor.execute(f"UPDATE {table_to_update} SET id = id - {max_id} WHERE id > ?", (position_of_row,))
            except: pass
            cursor.connection.commit()
            validation = True
        except Exception as e:
            print(e)

    send_data(client_sock, aes_key, validation)

def delete_row(client_sock, aes_key, cursor, table_to_update, position_of_row, user_write_table_names):
    validation = False
    if table_to_update in user_write_table_names:
        try:          
            cursor.execute(f"DELETE FROM {table_to_update} WHERE id = ?", (position_of_row,))
            cursor.connection.commit()        
            validation = True
        except Exception as e:
            print(e)
    send_data(client_sock, aes_key, validation)

def add_table(client_sock, aes_key, cursor, new_table_name, create_table_access, username, password, user_db_id, db_role):
    validation = False
    print(new_table_name)
    print(username)
    print(password)
    print(user_db_id)
    try:
        if create_table_access == "yes":
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            table_names = cursor.fetchall()
            current_table_names = []
            for tables in table_names:
                current_table_names.append(tables[0])
            
            if new_table_name not in current_table_names:
                if re.match(r'^[a-zA-Z0-9_]+$', new_table_name) is not None:
                    new_table_name = new_table_name.replace("'", "X")
                    new_table_name = new_table_name.replace('"', "X")
                    cursor.execute(f'''CREATE TABLE {new_table_name} (id INTEGER PRIMARY KEY AUTOINCREMENT)''')
                    if db_role != "admin":
                        cursor.execute(f'''SELECT write_access FROM {os.getenv('db_table_name')} WHERE username = ? AND password = ? AND id = ?''', (username, password, user_db_id))
                        new_write_access = cursor.fetchone()
                        new_write_access = f'{new_write_access[0]}, {new_table_name}'
                        cursor.execute(f'''UPDATE {os.getenv('db_table_name')} SET write_access = ? WHERE username = ? AND password = ? AND id = ?''', (new_write_access, username, password, user_db_id))
                    cursor.connection.commit()
                    validation = True
    except: pass
    send_data(client_sock, aes_key, validation)

def delete_table(client_sock, aes_key, cursor, del_table_data, user_write_table_names, password):
    validation = False
    try:
        print("Attempting to delete")
        safe_tables =  ['sqlite_master', 'sqlite_sequence', 'sqlite_stat', 'sqlite_temp_master', str(os.getenv('db_table_name')), str(os.getenv('db_firewall_name'))]
        del_table_name = del_table_data[0]
        attempted_pass = del_table_data[1]
        if del_table_name not in safe_tables:
            if attempted_pass == password and del_table_name in user_write_table_names:
                cursor.execute(f"DROP TABLE {del_table_name};")
                validation = True
    except: pass
    send_data(client_sock, aes_key, validation)


######################################## SOCKET SECURITY LAYER #######################################################

def close_connection(client_sock, conn_num, thread_id, db):
    client_sock.shutdown(socket.SHUT_RDWR)
    client_sock.close()

    if conn_num != None:
        try:
            db.close()
        except: pass
        with LOCK:
            thread = ACTIVE_THREADS.get(thread_id)
            if thread:
                del ACTIVE_THREADS[thread_id]
                print(f"Closing Connection: ({conn_num}) | Current Thread ({thread_id})")
                if thread["thread"] != threading.current_thread():  # Skip joining the current thread
                    thread["event"].set()
                    thread["thread"].join()
            else:
                print(f"Thread {thread_id} does not exist.")

    print(f"Connection {conn_num} closed.")

def generate_ssl_certificate(cert_file, key_file):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    cert = crypto.X509()
    cert.get_subject().CN = "AvailData"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha256")

    with open(cert_file, "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(key_file, "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    return cert_file, key_file

######################################## START-UP SCRIPT ###################################################

def main():
    global TOTAL_CONNECTIONS
    load_dotenv()

    # WRAP SOCKET IN SSL
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    if str(os.getenv("ca_cert_required")) == "True":
        cert_file = str(os.getenv("ca_cert_file"))
        key_file = str(os.getenv("ca_key_file"))
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.load_verify_locations(str(os.getenv("ca_verify_file")))
    else:
        cert_file = str(os.getenv("gen_cert_file"))
        key_file = str(os.getenv("gen_key_file"))
        generate_ssl_certificate(cert_file, key_file)
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)
        context.verify_mode = ssl.CERT_NONE

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((os.getenv("pub_Ip"), int(os.getenv("pub_port"))))
    ssl_server_socket = context.wrap_socket(server_socket, server_side=True)
    ssl_server_socket.listen()

    db = sqlite3.connect(f"database_container/{os.getenv('db_name')}")
    cursor = db.cursor()

    # GUARANTEE FIREWALL IS SET PROPERLY
    print("Server Online.")
    firewall_enabled = str(os.getenv("firewall_enabled")).lower()

    while True:
        client_sock, addr = ssl_server_socket.accept()
        print(f"incoming connection by: {addr}")

        #test if firewall enabled
        create_thread = True
        if firewall_enabled == "true":
            print("Firewall enabled")
            cursor.execute(f"SELECT is_blocked FROM {os.getenv('db_firewall_name')} WHERE ip_address = ?", (addr[0],))
            result = cursor.fetchone()

            if result is not None:
                is_blocked = result[0]
                if is_blocked:
                    close_connection(client_sock, None, None, None)
                    create_thread = False

        if create_thread:
            thread_id = len(ACTIVE_THREADS) + 1
            terminate_event = threading.Event()

            TOTAL_CONNECTIONS += 1
            conn_num = TOTAL_CONNECTIONS
            thread = threading.Thread(target=server_controller,
                                    args=(client_sock, addr[0], conn_num, thread_id,))  
            ACTIVE_THREADS[thread_id] = {"thread": thread, "event": terminate_event}
            thread.start()
            print(f'''Active Clients ({len(ACTIVE_THREADS)}) | Closed Clients ({TOTAL_CONNECTIONS - len(ACTIVE_THREADS)}) | Total: ({TOTAL_CONNECTIONS}).''')
        else:
            close_connection(client_sock, None, None, None)
            
if __name__ == "__main__":
    main()