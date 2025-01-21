#imports
import hashlib
import sqlite3
import random
import re
import subprocess
import os
import msvcrt
import sys
from datetime import datetime
from abc import ABC, abstractmethod

#Utilities
class utilities():
    #for hashing passwords and credentials
    def hash_value(value):
        return hashlib.sha256(value.encode()).hexdigest()

    #For determining owner, staff or users
    def find_user():
        
        # Fetch lists of credentials from database
        owner_list = database_Functions.owner()
        staff_list = database_Functions.staff()
        user_list = database_Functions.user()
        
        # Get the user input and hash it
        print("Enter Username/Card Number: ", end="", flush=True)
        user = utilities.capture_input()
        if user is None:
            utilities.clear_screen()
            print("Are you sure you want to exit?")
            print("Press Enter to Continue or ESC to Cancel")
            while True:
                key = msvcrt.getch()
                if key == b'\r':  
                    print("\nExiting system...")
                    sys.exit() 
                elif key == b'\x1b':
                    utilities.clear_screen()  
                    return screen.landingPage()
        if user.isdigit():
            hashed_user = user
        else:    
            hashed_user = utilities.hash_value(user)
        
        # Iterate through owner_list
        for credentials in owner_list:
            if hashed_user == credentials[1]:  # Check if hashed_user matches the username
                password = input("Enter Password/PIN: ")
                hashed_password = utilities.hash_value(password)
                if hashed_password == credentials[2]:  # Check if hashed_password matches the stored password
                    UserContext.set_user(credentials[0], "owner")
                    utilities.clear_screen()
                    print("Log In Succesful")
                    print("Welcome Owner!")
                    utilities.wait()
                    return True
        
        # Iterate through staff_list
        for credentials in staff_list:
            if hashed_user == credentials[1]:  # Check if hashed_user matches the username
                password = input("Enter Password/PIN: ")
                hashed_password = utilities.hash_value(password)
                if hashed_password == credentials[2]:  # Check if hashed_password matches the stored password
                    UserContext.set_user(credentials[0], "staff")
                    utilities.clear_screen()
                    print("Log In Succesful")
                    print("Welcome Staff!")
                    utilities.wait()
                    return True
        
        # Iterate through user_list
        for credentials in user_list:
            if hashed_user == credentials[1]:  # Check if hashed_user matches the username
                password = input("Enter Password/PIN: ")
                hashed_password = utilities.hash_value(password)
                if hashed_password == credentials[2]:  # Check if hashed_password matches the stored password
                    UserContext.set_user(credentials[0], "user")
                    utilities.clear_screen()
                    print("Log In Succesful")
                    print("Welcome User!")
                    utilities.wait()
                    return True
        
        return False
    
    #Exiting
    def capture_input():
        input_string = ""
        while True:
            char = msvcrt.getch()
            if char == b'\r':
                print()
                return input_string
            elif char == b'\x08': 
                if len(input_string) > 0:
                    input_string = input_string[:-1]
                    print("\b \b", end="", flush=True)
            elif char == b'\x1b':
                return None
            else:
                if char.decode().isprintable():
                    input_string += char.decode()
                    print(char.decode(), end="", flush=True)

    #For Password Validation
    def validate_password(password):
        if len(password) < 6:
            return "Password must be 6 characters or more"
        
        if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            return "Password must contain Alphanumeric Characters"
        
        if not re.search(r'[!@#$%^&*()_,.?":{}|<>]', password):
            return "Password must contain a symbol"
        return True

    #For PIN Validation
    def validate_pin(password):
        if password == "1234":
            return "PIN must be not 1234"
        if not password.isdigit():
            return "PIN must be valid number"
        if len(password) != 4:
            return "PIN must be 4 digits only"
        return True
    
    #Digit Validation
    def isDouble(value):
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    #For Generating Unique Card Number
    def generate_card_number():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        while True:
            temp = [str(random.randint(0, 9)) for _ in range(16)]
            card_number = ''.join(temp)
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE card_number = ?", (card_number,))
            if cursor.fetchone()[0] == 0:
                break
        
        conn.close()
        return card_number

    #For Clearing Screen
    def clear_screen():
        subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)
    
    #For Unique Staff Verification
    def staff_name():
        staff_list = database_Functions.staff()
        utilities.clear_screen()
        print("Staff Registration\n")
        
        name = input("Enter Name: ")
        
        for staff in staff_list:
            if staff[1].lower() == name.lower():
                print(f"Staff name '{name}' already registered.")

        return name
    
    #For Age verification
    def age():
        while True:
            utilities.clear_screen()
            print("Staff Registration\n")
            age = input("Enter Age: ")
            if age.isdigit():
                if(int(age) < 18):
                    utilities.clear_screen()
                    print("Staff Must Be 18 Years Old or Above")
                    utilities.wait()
                else:
                    return int(age)
            else:
                utilities.clear_screen()
                print("Invalid input. Please enter a valid age.")
                utilities.wait()
    
    #For Date verification
    def birthdate():
        while True:
            utilities.clear_screen()
            print("Staff Registration\n")
            birthday = input("Enter Birthday (YYYY-MM-DD): ")
            try:
                parsed_date = datetime.strptime(birthday, "%Y-%m-%d")
                return parsed_date.date()
            except ValueError:
                utilities.clear_screen()
                print("Invalid format. Please enter the date in YYYY-MM-DD format.")
                utilities.wait()
    
    #For Phone Verification
    def phone():
        while True:
            utilities.clear_screen()
            print("Staff Registration\n")
            phone = input("Enter Phone Number: ")
            if phone.isdigit():
                if phone.startswith("09"):
                    if (len(phone) == 11):
                        return phone
                    else:
                        utilities.clear_screen()
                        print("Phone number must contain 11 digits")
                        utilities.wait()
                else:
                    utilities.clear_screen()
                    print("Phone number must start with 09")
                    utilities.wait()
            else:
                utilities.clear_screen()
                print("Enter Valid Phone Number")
                utilities.wait()
    
    #For Email Verification
    def email():
        while True:
            utilities.clear_screen()
            print("Staff Registration\n")
            email = input("Enter Email: ")

            if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                return email
            else:
                utilities.clear_screen()
                print("Invalid email address. Please enter a valid email.")
                utilities.wait()
    
    #For User Name Verification
    def user_name():
        user_list = database_Functions.user()
        utilities.clear_screen()
        print("User Registration\n")
        
        name = input("Enter Name: ")
        
        for user in user_list:
            if user[1].lower() == name.lower():
                print(f"User '{name}' already registered.")

        return name
    
    #For User Age verification
    def user_age():
        while True:
            utilities.clear_screen()
            print("User Registration\n")
            age = input("Enter Age: ")
            if age.isdigit():
                if(int(age) < 18):
                    utilities.clear_screen()
                    print("User Must Be 18 Years Old or Above")
                    utilities.wait()
                else:
                    return int(age)
            else:
                utilities.clear_screen()
                print("Invalid input. Please enter a valid age.")
                utilities.wait()
    
    #For Date verification
    def user_birthdate():
        while True:
            utilities.clear_screen()
            print("User Registration\n")
            birthday = input("Enter Birthday (YYYY-MM-DD): ")
            try:
                parsed_date = datetime.strptime(birthday, "%Y-%m-%d")
                return parsed_date.date()
            except ValueError:
                utilities.clear_screen()
                print("Invalid format. Please enter the date in YYYY-MM-DD format.")
                utilities.wait()
    
    #For Phone Verification
    def user_phone():
        while True:
            utilities.clear_screen()
            print("User Registration\n")
            phone = input("Enter Phone Number: ")
            if phone.isdigit():
                if phone.startswith("09"):
                    if (len(phone) == 11):
                        return phone
                    else:
                        utilities.clear_screen()
                        print("Phone number must contain 11 digits")
                        utilities.wait()
                else:
                    utilities.clear_screen()
                    print("Phone number must start with 09")
                    utilities.wait()
            else:
                utilities.clear_screen()
                print("Enter Valid Phone Number")
                utilities.wait()
    
    #For Email Verification
    def user_email():
        while True:
            utilities.clear_screen()
            print("User Registration\n")
            email = input("Enter Email: ")

            if re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                return email
            else:
                utilities.clear_screen()
                print("Invalid email address. Please enter a valid email.")
                utilities.wait()
                    
    #For waiting    
    def wait():
        input("\nPress Any Key To Continue...")
        utilities.clear_screen()
        
#Context Class
class UserContext:
    current_user = None
    
    @staticmethod
    def set_user(user_id, role):
        UserContext.current_user = {
            "user_id": user_id,
            "role": role
        }
        
    @staticmethod
    def get_user():
        return UserContext.current_user
    
    @staticmethod
    def clear_user():
        UserContext.current_user = None

#ABC for Bank Owners, Staff and Users
class ATMUser(ABC):
    def __init__(self, user_id):
        self.user_id = user_id
    
    @abstractmethod
    def login(self):
        pass
    
#Bank Owner Class
class Owner(ATMUser):
    def __init__(self, user_id):
        super().__init__(user_id)
    
    def login(self):
        print("Welcome Owner")
        return 0
    
    def change_password(self, old_password):
        while True:
            utilities.clear_screen()
            print("Change Password\n")
            password = input("Enter old password: ")
            hashed_password = utilities.hash_value(password)
            
            if hashed_password == old_password:
                break
            else:
                utilities.clear_screen()
                print("Wrong Password!")
                utilities.wait()
        
        while True:
            utilities.clear_screen()
            print("Change Password\n")
            
            password = input("Enter New Password: ")
            confirm_password = input("Confirm Password:   ")
            
            if password == confirm_password:
                temp = utilities.validate_password(password)
                if temp == True:
                    database_Functions.owner_password(password)
                else:
                    utilities.clear_screen()
                    print(temp)
                    utilities.wait()
            else:
                utilities.clear_screen()
                print("Passwords Do Not Match!")
                utilities.wait() 

    def hire_staff(self):
        name = utilities.staff_name()
        age = utilities.age()
        birthday = utilities.birthdate()
        utilities.clear_screen()
        print("Staff Registration\n")
        address = input("Enter Address: ")
        phone = utilities.phone()
        email = utilities.email()
        
        database_Functions.staff_register(name, age, birthday, address, phone, email)
        
        return True

#Bank Staff Class    
class Staff(ATMUser):
    def __init__(self, user_id):
        super().__init__(user_id)
    
    def login(self):
        print("Staff Logged In")
        return 0
    
    def change_password(self, old_password):
        while True:
            utilities.clear_screen()
            print("Change Password\n")
            password = input("Enter old password: ")
            hashed_password = utilities.hash_value(password)
            
            if hashed_password == old_password:
                break
            else:
                utilities.clear_screen()
                print("Wrong Password!")
                utilities.wait()
        
        while True:
            utilities.clear_screen()
            print("Change Password\n")
            
            password = input("Enter New Password: ")
            confirm_password = input("Confirm Password:   ")
            
            if password == confirm_password:
                temp = utilities.validate_password(password)
                if temp == True:
                    database_Functions.staff_password(password)
                else:
                    utilities.clear_screen()
                    print(temp)
                    utilities.wait()
            else:
                utilities.clear_screen()
                print("Passwords Do Not Match!")
                utilities.wait()                
    
    def register_user(self):
        name = utilities.user_name()
        age = utilities.user_age()
        birthday = utilities.user_birthdate()
        utilities.clear_screen()
        print("User Registration\n")
        address = input("Enter Address: ")
        phone = utilities.user_phone()
        email = utilities.user_email()
        
        database_Functions.user_register(name, age, birthday, address, phone, email)
        
        return True

#Bank User Class    
class User(ATMUser):
    def __init__(self, user_id):
        super().__init__(user_id)
        
    def login(self):
        print("User Logged In")
        return 0
    
    def view_details(self, user_id):
        utilities.clear_screen()
        
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE user_id = ?",(user_id,))
        result = cursor.fetchone()
        
        print("User Information\n")
        print("Name ", result[1])
        print("Age ", result[2])
        print("Address ", result[3])
        print("Birthday ", result[6])
        print("Phone ", result[7])
        print("Email ", result[8])
        
        utilities.wait()
        return screen.routePage()
    
    def view_transactions(self, user_id):
        utilities.clear_screen()
        
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT t.transaction_id, t.transaction_type, t.amount, t.timestamp, t.balance_after, COALESCE(s.name, 'N/A')
            FROM transactions t
            LEFT JOIN staff s ON t.staff_id = s.staff_id
            WHERE t.user_id = ?
            ORDER BY t.timestamp DESC
        """, (user_id,))
        results = cursor.fetchall()
        
        print("Transactions\n")
        for result in results:
            print(f"Transaction ID: {result[0]}")
            print(f"Transaction Type: {result[1]}")
            print(f"Amount: ₱{result[2]}")
            print(f"Balance After: ₱{result[4]}")
            print(f"Timestamp: {result[3]}")
            print(f"Staff Name: {result[5]}\n")
        
        utilities.wait()
        return screen.routePage()
    
    def change_password(self, pin):
        while True:
            utilities.clear_screen()
            print("Change Password\n")
            password = input("Enter old PIN: ")
            hashed_password = utilities.hash_value(password)
            
            if hashed_password == pin:
                break
            else:
                utilities.clear_screen()
                print("Wrong PIN!")
                utilities.wait()
        
        while True:
            utilities.clear_screen()
            print("Change PIN\n")
            
            password = input("Enter New PIN: ")
            confirm_password = input("Confirm PIN:   ")
            
            if password == confirm_password:
                temp = utilities.validate_pin(password)
                if temp == True:
                    database_Functions.user_password(password)
                else:
                    utilities.clear_screen()
                    print(temp)
                    utilities.wait()
            else:
                utilities.clear_screen()
                print("Passwords Do Not Match!")
                utilities.wait()
    
    def withdraw(self, user_id):
        utilities.clear_screen()
        balance = database_Functions.fetch_balance()
        Balance = float(balance)
        
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        if Balance == 0:
            utilities.clear_screen()
            print("Insufficient Funds. Please Proceed to a staff to deposit")
            utilities.wait()
            screen.routePage()
        
        while True:
            print("Withdraw\n")
            print("Actual Balance:₱", balance)
            print("Withdrawal Amount:₱ ", end="", flush=True)
            withdraw = utilities.capture_input()
            if withdraw == None:
                screen.routePage()
            if utilities.isDouble(withdraw):
                number = float(withdraw)
                if number > Balance:
                    utilities.clear_screen()
                    print("Insufficient Funds")
                    utilities.wait()
                else:
                    break 
            else:
                utilities.clear_screen()
                print("Invalid Deposit")
                utilities.wait()
        
        utilities.clear_screen()
        balance_after = Balance - number
        
        print("Withdrawal Receipt\n")
        print("Actual Balance:₱", balance)
        print("Withdrawal Amount:₱ ", withdraw)
        print("Balance After Withdrawal:₱ ", balance_after)
        
        print("\nPress Enter to Continue or ESC to Cancel")
        while True:
            key = msvcrt.getch()
            if key == b'\r':  
                try:
                    transaction_type = "withdraw"
                    cursor.execute(
                        "INSERT INTO transactions(user_id, staff_id, transaction_type, amount, balance_after) VALUES (?,?,?,?,?)",
                        (user_id, 0, transaction_type, number, balance_after)
                    )
                    cursor.execute("UPDATE users SET balance = ? WHERE user_id = ?",(balance_after, user_id))
                    
                    conn.commit()
                    
                    utilities.clear_screen()
                    print("Withdrawal Successful!")
                    utilities.wait()
                except sqlite3.Error as e:
                    utilities.clear_screen()
                    print(f"\nError on withdrawal: {e}")
                    utilities.wait()
                finally:
                    conn.close()
                    return screen.routePage()
            elif key == b'\x1b':
                utilities.clear_screen()  
                return screen.routePage()
    
#Database Functions
class database_Functions():
    #Database Initialization
    def db():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        #Users Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            address VARCHAR NOT NULL,
            card_number TEXT NOT NULL UNIQUE,
            pin VARCHAR NOT NULL,
            birthday DATE NOT NULL,
            phone VARCHAR NOT NULL UNIQUE,
            email VARCHAR NOT NULL UNIQUE,
            balance REAL DEFAULT 0.0
        )
        ''')
        
        #Staff Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS staff (
            staff_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER NOT NULL,
            birthday DATE NOT NULL,
            address VARCHAR NOT NULL,
            phone VARCHAR NOT NULL,
            email VARCHAR NOT NULL,
            username VARCHAR NOT NULL UNIQUE,
            password VARCHAR NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        #Transaction Table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount NUMERIC NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            balance_after NUMERIC NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
            FOREIGN KEY (staff_id) REFERENCES staff (staff_id) ON DELETE CASCADE
        )
        ''')
        
        #Bank Owner
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS owner (
            owner_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR NOT NULL UNIQUE,
            password VARCHAR NOT NULL
        )
        ''')
        
        username = utilities.hash_value("admin")
        password = utilities.hash_value("admin1234")
        cursor.execute("SELECT COUNT(*) FROM owner WHERE username = ?", (username,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("INSERT INTO owner (username, password) VALUES (?, ?)", (username, password))
        
        conn.commit()
        conn.close()

    #Fetching owner database
    def owner():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM owner")
        rows = cursor.fetchall()
        credentials_list = [list(row) for row in rows]
        
        cursor.close()
        conn.close()
        
        return credentials_list

    #Fetching staff database
    def staff():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT staff_id, username, password FROM staff")
        rows = cursor.fetchall()
        credentials_list = [list(row) for row in rows]
        
        cursor.close()
        conn.close()
        
        return credentials_list
    
    #Fetching user database
    def user():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id, card_number, pin FROM users")
        rows = cursor.fetchall()
        credentials_list = [list(row) for row in rows]
        
        cursor.close()
        conn.close()
        
        return credentials_list

    #For registering user
    def staff_register(name, age, birthday, address, phone, email):
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        utilities.clear_screen()
        
        list = database_Functions.staff()
        count = len(list)
        
        print("Staff Information\n")
        print("Name:     ", name)
        print("Age:      ", age)
        print("Birthday: ", birthday)
        print("Address:  ", address)
        print("Phone:    ", phone)
        print("Email:    ", email)
        print("\nPress Enter to Continue or Esc to Cancel")
        
        while True:
            key = msvcrt.getch()
            if key == b'\r':  
                username = "staff" + str(count + 1)
                password = "staff_"+ str(count + 1)
                hashed_username = utilities.hash_value(username)
                hashed_password = utilities.hash_value(password)
                
                try:
                    cursor.execute(
                        "INSERT INTO staff(name, age, birthday, address, phone, email, username, password) VALUES (?,?,?,?,?,?,?,?)",
                        (name, age, birthday, address, phone, email, hashed_username, hashed_password)
                    )
                    conn.commit()
                    utilities.clear_screen()
                    print(f"\nStaff '{name}' registered successfully!\n")
                    print(f"Username: {username}")
                    print(f"Temporary Password: {password}")
                    utilities.wait()
                except sqlite3.Error as e:
                    utilities.clear_screen()
                    print(f"\nError while registering staff: {e}")
                    utilities.wait()
                finally:
                    conn.close()
                    return screen.routePage()
            elif key == b'\x1b':
                utilities.clear_screen()  
                print("\nRegistration canceled.")
                utilities.wait()
                conn.close()
                return screen.routePage()

    #For Changing Staff Password
    def staff_password(password):
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        utilities.clear_screen()
        temp = UserContext.get_user()
        
        staff_id = temp["user_id"]
        hashed_password = utilities.hash_value(password)
        
        try:
            cursor.execute(
                "UPDATE staff SET password = ? WHERE staff_id = ?",
                (hashed_password, staff_id)
            )
            conn.commit()
            
            utilities.clear_screen()
            print("Password successfully updated.")
            utilities.wait()
        except Exception as e:
            utilities.clear_screen()
            print("An error occurred while updating the password:", str(e))
            utilities.wait()
            screen.staffDashboard()
        finally:
            cursor.close()
            conn.close()
            screen.routePage()
    
    def owner_password(password):
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        utilities.clear_screen()
        temp = UserContext.get_user()
        
        owner_id = temp["user_id"]
        hashed_password = utilities.hash_value(password)
        
        try:
            cursor.execute(
                "UPDATE owner SET password = ? WHERE owner_id = ?",
                (hashed_password, owner_id)
            )
            conn.commit()
            
            utilities.clear_screen()
            print("Password successfully updated.")
            utilities.wait()
        except Exception as e:
            utilities.clear_screen()
            print("An error occurred while updating the password:", str(e))
            utilities.wait()
            screen.routePage()
        finally:
            cursor.close()
            conn.close()
            screen.routePage()

    #For Fetching Staff Password
    def fetch_staff():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        temp = UserContext.get_user()
        staff_id = temp["user_id"]
        
        cursor.execute("SELECT password FROM staff WHERE staff_id = ?",(staff_id,))
        password = cursor.fetchone()
        
        conn.close()
        return password[0]
    
    #For Fetching Owner Password
    def fetch_owner():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        temp = UserContext.get_user()
        owner_id = temp["user_id"]
        
        cursor.execute("SELECT password FROM owner WHERE owner_id = ?",(owner_id,))
        password = cursor.fetchone()
        
        conn.close()
        return password[0]

    
    #For registering user
    def user_register(name, age, birthday, address, phone, email):
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        utilities.clear_screen()
        
        while True:
            print("User Must Deposit to Open an Account\n")
            
            print("Enter Deposit: ₱ ", end="", flush=True)
            balance = utilities.capture_input()
            if balance == None:
                screen.routePage()
            
            if utilities.isDouble(balance):
                number = float(balance)
                if number < 5000:
                    utilities.clear_screen()
                    print("Deposit must be at least ₱5000")
                    utilities.wait()
                else:
                    break 
            else:
                utilities.clear_screen()
                print("Invalid Deposit")
                utilities.wait()
        
        utilities.clear_screen()        
        print("User Information\n")
        print("Name:     ", name)
        print("Age:      ", age)
        print("Birthday: ", birthday)
        print("Address:  ", address)
        print("Phone:    ", phone)
        print("Email:    ", email)
        print("Balance: ₱", number)
        print("\nPress Enter to Continue or Esc to Cancel")
        
        while True:
            key = msvcrt.getch()
            if key == b'\r':
                temp = UserContext.get_user()
                staff_id = temp["user_id"]  
                card_number = utilities.generate_card_number()
                pin = "1234"
                hashed_pin = utilities.hash_value(pin)
                
                try:
                    cursor.execute(
                        "INSERT INTO users(name, age, address, card_number, pin, birthday, phone, email, balance) VALUES (?,?,?,?,?,?,?,?,?)",
                        (name, age, address, card_number, hashed_pin, birthday, phone, email, balance)
                    )
                    user_id = cursor.lastrowid
                    
                    transaction_type = "deposit"
                    cursor.execute(
                        "INSERT INTO transactions(user_id, staff_id, transaction_type, amount, balance_after) VALUES (?,?,?,?,?)",
                        (user_id, staff_id, transaction_type, balance, balance)
                    )
                    
                    conn.commit()
                    utilities.clear_screen()
                    print(f"\nUser '{name}' registered successfully!\n")
                    print("Please Take Note Of Your Card Number")
                    print(f"Card Number: {card_number}")
                    print(f"Temporary PIN: {pin}")
                    utilities.wait()
                except sqlite3.Error as e:
                    utilities.clear_screen()
                    print(f"\nError while registering user: {e}")
                    utilities.wait()
                finally:
                    conn.close()
                    return screen.routePage()
            elif key == b'\x1b':
                utilities.clear_screen()  
                print("\nRegistration canceled.")
                utilities.wait()
                conn.close()
                return screen.routePage()

    #For Changing User Password
    def user_password(pin):
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        utilities.clear_screen()
        temp = UserContext.get_user()
        
        user_id = temp["user_id"]
        hashed_pin = utilities.hash_value(pin)
        
        try:
            cursor.execute(
                "UPDATE users SET pin = ? WHERE user_id = ?",
                (hashed_pin, user_id)
            )
            conn.commit()
            
            utilities.clear_screen()
            print("Password successfully updated.")
            utilities.wait()
        except Exception as e:
            utilities.clear_screen()
            print("An error occurred while updating the password:", str(e))
            utilities.wait()
            screen.userDashboard()
        finally:
            cursor.close()
            conn.close()
            screen.routePage()                           

    #For Fetching User PIN
    def fetch_user():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        temp = UserContext.get_user()
        user_id = temp["user_id"]
        
        cursor.execute("SELECT pin FROM users WHERE user_id = ?",(user_id,))
        password = cursor.fetchone()
        
        conn.close()
        return password[0]

    #Fetching Balance
    def fetch_balance():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        temp = UserContext.get_user()
        user_id = temp["user_id"]
        
        cursor.execute("SELECT balance FROM users WHERE user_id = ?",(user_id,))
        balance = cursor.fetchone()
        
        conn.close()
        return balance[0]
#For Listings
class fetch_list():
    #Fetching User List
    def user_list():
        utilities.clear_screen()
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        
        if len(rows) == 0:
            utilities.clear_screen()
            print("No Records")
            utilities.wait()
            return screen.routePage()
        
        print("User List\n")
        for index, row in enumerate(rows, start=1):
            print(f"{index}. {row[1]}")
            
        print("Choose User: ", end="", flush=True)
        opt = utilities.capture_input()
        if opt == None:
            screen.routePage()
            
        user_id = rows[int(opt) - 1][0]

        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        user_info = cursor.fetchone()

        utilities.clear_screen()
        print("\nUser Information\n")
        print("Name:     ", user_info[1])
        print("Age:      ", user_info[2])
        print("Birthday: ", user_info[6])
        print("Address:  ", user_info[3])
        print("Phone:    ", user_info[7])
        print("Email:    ", user_info[8])
        print("Balance:  ", user_info[9])
        
        cursor.execute("""
            SELECT t.transaction_id, t.transaction_type, t.amount, t.timestamp, t.balance_after, COALESCE(s.name, 'N/A')
            FROM transactions t
            LEFT JOIN staff s ON t.staff_id = s.staff_id
            WHERE t.user_id = ?
        """, (user_id,))
        transactions = cursor.fetchall()

        if transactions:
            print("\nTransaction History\n")
            for txn in transactions:
                print(f"Transaction ID: {txn[0]}")
                print(f"Transaction Type: {txn[1]}")
                print(f"Amount:₱ {txn[2]}")
                print(f"Timestamp: {txn[3]}")
                print(f"Balance After:₱ {txn[4]}")
                print(f"Staff Name: {txn[5]}\n")
        else:
            print("\nNo transactions found for this user.")
        
        print("\nPress Enter to Go Back to List or Esc to Go Back to the Menu")
        key = msvcrt.getch()
        if key == b'\x1b': 
            conn.close()
            screen.routePage()
        elif key == b'\r':  
            fetch_list.user_list()
    
    #Fetching Staff
    def staff_list():
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM staff")
        rows = cursor.fetchall()
        
        if len(rows) == 0:
            utilities.clear_screen()
            print("No Records")
            utilities.wait()
            return screen.routePage()
        
        utilities.clear_screen()
        print("Staff List\n")
        for index, row in enumerate(rows, start=1):
            print(f"{index}. {row[1]}")
            
        print("Choose Staff: ", end="", flush=True)
        opt = utilities.capture_input()
        if opt == None:
            screen.routePage()
            
        staff_id = rows[int(opt) - 1][0]

        cursor.execute("SELECT * FROM staff WHERE staff_id = ?", (staff_id,))
        staff_info = cursor.fetchone()

        utilities.clear_screen()
        print("\nStaff Information\n")
        print("Name:     ", staff_info[1])
        print("Age:      ", staff_info[2])
        print("Birthday: ", staff_info[3])
        print("Address:  ", staff_info[4])
        print("Phone:    ", staff_info[5])
        print("Email:    ", staff_info[6])
        created_at_str = staff_info[9]
        created_at = datetime.strptime(created_at_str, '%Y-%m-%d %H:%M:%S')
        print("Hired on: ", created_at.date())
        
        cursor.execute("""
            SELECT t.transaction_id, t.transaction_type, t.amount, t.timestamp, t.balance_after, u.name
            FROM transactions t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.staff_id = ?
        """, (staff_id,))
        transactions = cursor.fetchall()

        if transactions:
            print("\nTransaction History\n")
            for txn in transactions:
                print(f"Transaction ID: {txn[0]}")
                print(f"Transaction Type: {txn[1]}")
                print(f"User Name: {txn[5]}")
                print(f"Amount: {txn[2]}")
                print(f"Timestamp: {txn[3]}")
                print(f"Balance After: {txn[4]}\n")
        else:
            print("\nNo transactions found for this user.")
        
        print("\nPress Enter to Go Back to List or Esc to Go Back to the Menu")
        key = msvcrt.getch()
        if key == b'\x1b': 
            conn.close()
            screen.routePage()
        elif key == b'\r':  
            fetch_list.staff_list()

    #Fetching User List for Deposit
    def deposit():
        utilities.clear_screen()
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users")
        rows = cursor.fetchall()
        
        if len(rows) == 0:
            utilities.clear_screen()
            print("No Records")
            utilities.wait()
            return screen.routePage()
        
        print("User List\n")
        for index, row in enumerate(rows, start=1):
            print(f"{index}. {row[1]}")
            
        print("Choose User: ", end="", flush=True)
        opt = utilities.capture_input()
        if opt == None:
            screen.routePage()
            
        user_id = rows[int(opt) - 1][0]
        
        utilities.clear_screen()
        
        cursor.execute("SELECT * FROM users WHERE user_id = ?",(user_id,))
        result = cursor.fetchone()
        
        print("User Account\n")
        print("Actual Balance:₱", result[9])
        
        while True:
            amount = input("Deposit Amount:₱ ")
            if utilities.isDouble(amount):
                number = float(amount)
                break
            else:
                utilities.clear_screen()
                print("Invalid Deposit")
                utilities.wait()
        
        actual = int(result[9])
        balance = actual + number
        
        temp=UserContext.get_user()
        staff_id = temp["user_id"]
        
        utilities.clear_screen()
        print("Deposit Receipt\n")
        print("Actual Balance:₱ ", result[9])
        print("Amount to be Deposited:₱", amount)
        print("Balance after making the deposit:₱", balance)
        
        print("\nPress Enter to Continue or ESC to Cancel")
        while True:
            key = msvcrt.getch()
            if key == b'\r':  
                try:
                    transaction_type = "deposit"
                    cursor.execute(
                        "INSERT INTO transactions(user_id, staff_id, transaction_type, amount, balance_after) VALUES (?,?,?,?,?)",
                        (user_id, staff_id, transaction_type, number, balance)
                    )
                    cursor.execute("UPDATE users SET balance = ? WHERE user_id = ?",(balance, user_id))
                    
                    conn.commit()
                    
                    utilities.clear_screen()
                    print("Deposit Successful!")
                    utilities.wait()
                except sqlite3.Error as e:
                    utilities.clear_screen()
                    print(f"\nError on depositing: {e}")
                    utilities.wait()
                finally:
                    conn.close()
                    return screen.routePage()
            elif key == b'\x1b':
                utilities.clear_screen()  
                return screen.routePage()
        
#First Login
class first_login:   
    def staff_login():
        temp = UserContext.get_user()
        staff_id = temp["user_id"]
        
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT password FROM staff where staff_id = ?", (staff_id,))
        result = cursor.fetchone()
        
        first_password = "staff_" + str(staff_id)
        default_password = utilities.hash_value(first_password)
        stored = result [0]
        
        if stored == default_password:
            utilities.clear_screen
            print("You need to change your password first to continue!")
            utilities.wait()
            
            staff = Staff(staff_id)
            staff.change_password(stored)
            
        return True
    
    def user_login():
        temp = UserContext.get_user()
        user_id = temp["user_id"]
        
        conn = sqlite3.connect('atm.db')
        cursor = conn.cursor()
        
        cursor.execute("SELECT pin FROM users where user_id = ?", (user_id,))
        result = cursor.fetchone()
        
        first_pin = "1234"
        default_pin = utilities.hash_value(first_pin)
        stored = result [0]
        
        if stored == default_pin:
            utilities.clear_screen
            print("You need to change your PIN first to continue!")
            utilities.wait()
            
            user = User(user_id)
            user.change_password(stored)
            
        return True
            
#For Different Screens
class screen():
    @staticmethod
    def landingPage():
        print("Welcome to Kwatro's ATM/Bank Management System")
        print("Please log in.\n")
        
        # Loop until the user successfully logs in
        while True:
            if utilities.find_user():
                break
            else:
                utilities.clear_screen()
                print("\nInvalid credentials. Please try again.\n")
                utilities.wait()
                screen.landingPage()

        screen.routePage()
        
    @staticmethod
    def routePage():
        current_user = UserContext.get_user()
        if current_user:
            role = current_user["role"]
            if role == "owner":
                screen.ownerDashboard()
            elif role == "staff":
                screen.staffDashboard()
            elif role == "user":
                screen.userDashboard()

    @staticmethod
    def ownerDashboard():
        utilities.clear_screen()
        print("\n=== Kwatro's Enterprise ===\n")
        print("1. View All Staffs")
        print("2. View All Users")
        print("3. Hire Staff")
        print("4. Change Password")
        print("5. Logout")
        choice = input("\nEnter your choice: ")
        if choice == "5":
            UserContext.clear_user()
            utilities.clear_screen()
            print("\nLogged out successfully.\n")
            utilities.wait()
            screen.landingPage()
        elif choice == "4":
            temp=UserContext.get_user()
            owner_id = temp["user_id"]
            owner = Owner(owner_id)
            password = database_Functions.fetch_owner()
            owner.change_password(password)
        elif choice == "3":
            current_user = UserContext.get_user()
            user_id = current_user["user_id"]
            owner = Owner(user_id)
            owner.hire_staff()
        elif choice == "2":
            fetch_list.user_list()
        elif choice == "1":
            fetch_list.staff_list()
        else:
            utilities.clear_screen()
            print("Invalid Input, Try again")
            utilities.wait()
            return screen.routePage()
            
    @staticmethod
    def staffDashboard():
        
        first_login.staff_login()
        
        utilities.clear_screen()
        print("\n=== Staff Dashboard ===")
        print("1. View User Details")
        print("2. Register User")
        print("3. User Deposit")
        print("4. Change Password")
        print("5. Logout")
        choice = input("Enter your choice: ")
        if choice == "5":
            UserContext.clear_user()
            utilities.clear_screen()
            print("\nLogged out successfully.\n")
            utilities.wait()
            screen.landingPage()
        elif choice == "4":
            temp=UserContext.get_user()
            staff_id = temp["user_id"]
            staff = Staff(staff_id)
            password = database_Functions.fetch_staff()
            staff.change_password(password)
        elif choice == "3":
            fetch_list.deposit()
        elif choice == "2":
            temp=UserContext.get_user()
            staff_id = temp["user_id"]
            staff = Staff(staff_id)
            staff.register_user()
        elif choice == "1":
            fetch_list.user_list()

    @staticmethod
    def userDashboard():
        utilities.clear_screen()
        
        first_login.user_login()
        
        balance = database_Functions.fetch_balance()
        print("Balance:₱", balance)
        
        print("\n=== User Dashboard ===")
        print("1. View Account Details")
        print("2. View Transactions")
        print("3. Withdraw Money")
        print("4. Change Password")
        print("5. Logout")
        choice = input("Enter your choice: ")
        if choice == "5":
            UserContext.clear_user()
            utilities.clear_screen()
            print("\nLogged out successfully.\n")
            utilities.wait()
            screen.landingPage()
        elif choice == "3":
            temp=UserContext.get_user()
            user_id = temp["user_id"]
            user = User(user_id)
            user.withdraw(user_id)
        elif choice == "4":
            temp=UserContext.get_user()
            user_id = temp["user_id"]
            user = User(user_id)
            password = database_Functions.fetch_user()
            user.change_password(password)
        elif choice == "2":
            temp=UserContext.get_user()
            user_id = temp["user_id"]
            user = User(user_id)
            user.view_transactions(user_id)
        elif choice == "1":
            temp=UserContext.get_user()
            user_id = temp["user_id"]
            user = User(user_id)
            user.view_details(user_id)

# Main function
def main():
    database_Functions.db()  # Initialize the database
    screen.landingPage()     # Start the landing page

if __name__ == "__main__":
    utilities.clear_screen()
    main()
