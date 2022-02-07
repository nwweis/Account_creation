import sys
import os
import re
import hashlib
import sqlite3

# Config
db_path = 'login_db.db'

## SQL DATABASE ##
def create_con(db_path): # Called from main()
    con = None

    try:
        con = sqlite3.connect(db_path)
    except Exception as e:
        print(f"Database connection error: {e}")

    query = ('''SELECT count(name) login 
                FROM sqlite_master 
                WHERE type='table' 
                AND name='login';''')

    result = con.execute(query)

    if result.fetchone()[0] == 0:
        print("Creating login table")
        create_table = '''CREATE TABLE IF NOT EXISTS login(
                            id integer PRIMARY KEY, 
                            username text, 
                            password text);'''

        con.execute(create_table)
        con.commit()

    return con

def check_un(un, dbconn): # Called from raw_input()
    exist = False # Variable default to false indicating account doesnt exist
    result = dbconn.execute('''SELECT * FROM login where username=:un''', {"un": un}) # Select row based on username input
    un_db = result.fetchall()

    if len(un_db) != 0: # If table not empty, username exist
        exist = True
    
    return exist
    

def create_login(un, hash_pw, dbconn): # Called from account()
    args = (un, hash_pw)
    query = '''INSERT INTO login (username, password) VALUES (?, ?)'''
    dbconn.execute(query, args)# Insert new username and hashed password row to login table
    
    print("Account created")


def search_login(un, hash_pw, dbconn): # Called from account()
    login = False # Variable to indicated login status
    result = dbconn.execute('''SELECT * FROM login where username=:un''', {"un": un}) # Select row based on username input
    login = result.fetchall()

    for _ in login:
        if _[1] == hash_pw: # Match user password input with database password
            login = True
 
    if login:
        print("Login successful")
    else:
        print("Check username or password")
    
    return login # TODO: return login token if required


def delete_account(un, hash_pw, dbconn):
    status = search_login(un, hash_pw, dbconn)
    
    if status:
        confirm_del = str(input("Please confirm by account deletion by entering password: "))
        confirm_hash = hash_legal(confirm_del)
        confirm = False
        
        result = dbconn.execute('''SELECT * FROM login where username=:un''', {"un": un}) # Select row based on username input
        login = result.fetchall()
        for _ in login:
            if _[1] == confirm_hash: # Match user password input with database password
                confirm = True
        
        if confirm:
            dbconn.execute('''DELETE FROM login where username=:un''', {"un": un})
        
        return("Account deleted")

    else:
        return "Password does not match, account not removed."

## USER INPUT ##
# Ask for user input
def raw_input(option, dbconn): # Called from account()
    while True:
        raw_un = str(input("Please enter username: ")) # User input
        if check_un(raw_un, dbconn): # If account exist in database
            if option == 'create':
                print("Please enter a different username.")
            else:
                break
        else: # If account does notexist in database
            if option == 'login':
                print("Account doesnt exist.")
            else:
                break
    while True:
        raw_pw = str(input("Please enter password: ")) # User input
        if check_illegal(raw_pw) == False: # Check if password matches requirements
            break   
    hash_pw = hash_legal(raw_pw) # Hash legal password
    return raw_un, hash_pw

# Sanitisation
def check_illegal(raw_pw): # Called from and returned to raw_input()
    # Check for empty string
    if not raw_pw:
        print("Password field cannot be empty")
        return True
    # Check password length
    elif len(raw_pw) <= 7:
        print("Password length must be more than 8 characters")
        return True
    # Checks for at least 1 number, 1 alpha(both upper and lower)
    elif re.search('^(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])', raw_pw) is None:
        print("Password must contain at least 1 uppercase and lowercase letter, number and special character.")
        return True
    # Input is legal
    else:    
        return False

# Hashing passwords using SHA256
def hash_legal(legal_input): # Called from raw_input()
    return hashlib.sha256(legal_input.encode('utf-8')).hexdigest()


## CREATE OR LOGIN TO ACCOUNT ##
def account(option, dbconn): # Called from Main()
    un, hash_pw = raw_input(option, dbconn)
    if option == 'login':
        search_login(un, hash_pw, dbconn) # Complete refactoring
    elif option == 'create':
        create_login(un, hash_pw, dbconn) # Complete refactoring
    elif option == 'delete':
        print(delete_account(un, hash_pw, dbconn))


## MAIN ##
def main():
    # Check if database exist, otherwise create database. Create connection.
    # db_path = 'login_db.db'
    # if not os.path.exists(db_path):
    #     create_db(db_path)

    dbconn = create_con(db_path)
    
    # Main Function
    while True:
        option = (input("Please select from 'create', 'login', 'delete' or 'exit': ")).lower().strip()
        if option == "exit":
            print("Exiting program")
            break
        elif option == 'create': 
            account('create', dbconn)
            break
        elif option == 'login':
            account('login', dbconn)
            break
        elif option == 'delete':
            account('delete', dbconn)
            break
        else:
            print("Please select correct option")

    dbconn.commit()
    dbconn.close()
            
if __name__ == "__main__":
    main()
    print("Program ran to completion")