#!/usr/bin/env python3

import os
import sys

# Get the absolute path of the directory containing this script
script_dir = os.path.dirname(os.path.realpath(__file__))

# Append the parent directory (containing PasswordUtility module) to sys.path
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
password_manager_dir = os.path.join(parent_dir, 'Documents/GitHub/Password-Manager')
sys.path.append(password_manager_dir)


import pwinput
from PasswordUtility import *
from vault_utility import VaultUtility

MASTER_PASSWORD_FILE_NAME = 'master_password.json'
current_vault = None
master_password = None
vault_name = None
encryption_key = None


class PasswordManager:
    def create_password_vault(self, vault_name, vault_password, vault_password_confirm):
        if vault_password != vault_password_confirm:
            return "Password do not match. Please try again"
        try:
            with open(MASTER_PASSWORD_FILE_NAME, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            data = {}

        if data.get(vault_name):
            return "Password vault already exist. Please try again."

        encryption_result = PasswordUtility().encrypt_password(vault_password)
        encrypted_vault_password, encryption_key = (encryption_result['encrypted_data'],
                                                    encryption_result['encryption_key'])
        data[vault_name] = {"password": encrypted_vault_password, "encryption_key": encryption_key}

        with open(MASTER_PASSWORD_FILE_NAME, 'w') as file:
            json.dump(data, file, indent=4)

        return "Password vault created successfully."

    def sign_in_to_password_vault(self, name, password):
        global current_vault, vault_name, master_password, encryption_key
        try:
            with open(MASTER_PASSWORD_FILE_NAME, 'r') as file:
                data = json.load(file)
        except FileNotFoundError:
            print("Vault Not Found. Please try again.")
            return

        if not data.get(name):
            print("Vault Not Found. Please try again.")
            return

        encrypted_vault_password, encryption_key = data[name]['password'], data[name]['encryption_key']
        decrypted_vault_password = PasswordUtility().decrypt_password(encrypted_vault_password,
                                                                      base64.b64decode(encryption_key))

        if password == decrypted_vault_password:
            current_vault = VaultUtility().load_vault(name)
            vault_name = name
            master_password = password
            encryption_key = encryption_key
            print("Sign In Successful")
        else:
            print("Password Incorrect. Please try again.")

    def add_password_to_vault(self, entity_identifier, entity_name, entity_password):
        global current_vault, vault_name, master_password, encryption_key
        if current_vault is None:
            print("Please sign in to a vault first.")
            return

        encrypted_password = PasswordUtility().encrypt_password(entity_password, base64.b64decode(encryption_key))
        new_entry = {entity_identifier: {'username': entity_name, 'password': encrypted_password['encrypted_data']}}
        current_vault.update(new_entry)
        VaultUtility.save_vault(vault_name, current_vault)
        print(f"New field added successfully to {vault_name}")

    def fetch_password_from_vault(self, entity_name):
        global current_vault, encryption_key
        if current_vault is None:
            print("Please sign in to a vault first.")
            return

        if not current_vault.get(entity_name):
            print("Entity Not Found. Please try again")
            return

        username, password = current_vault[entity_name]['username'], current_vault[entity_name]['password']
        decrypted_password = PasswordUtility().decrypt_password(password, base64.b64decode(encryption_key))
        print(f"For #{entity_name} record")
        print(f"The username: is {username}")
        print(f"The password: is {decrypted_password}")


def timeout_handler(signum, frame):
    global current_vault, master_password
    print("\nSession timed out. You have been signed out.")
    current_vault = None
    master_password = None
    signal.signal(signal.SIGALRM, signal.SIG_DFL)


if __name__ == '__main__':
    while True:
        print("What would you like to do?")
        print("1. Create a new password vault")
        print("2. Sign in to a password vault")
        print("3. Add a password to a vault")
        print("4. Fetch a password from a vault")
        print("5. Quit")

        input_arg = int(input())
        pw_manager = PasswordManager()
        # Create a new vault
        if input_arg == 1:
            name = input("Please provide a name for the vault:")
            password = pwinput.pwinput(prompt='Please enter a master password: ', mask='*')
            password_confirm = pwinput.pwinput(prompt='Please confirm the master password: ', mask='*')
            result = pw_manager.create_password_vault(name, password, password_confirm)
            print(result)
        # Sign in to an existing vault
        elif input_arg == 2:
            name = input("Enter Vault Name: ")
            password = pwinput.pwinput(prompt='Enter Vault Password: ', mask='*')
            pw_manager.sign_in_to_password_vault(name, password)
            if current_vault is not None:
                # Set a timeout of 1 minutes (60 seconds)
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(300)  # in seconds
        # Add a new entry in the vault
        elif input_arg == 3:
            identifier = input("Please provide unique name to identify the record:")
            name = input("Please enter the name:")
            password = pwinput.pwinput(prompt='Please enter the password: ', mask='*')
            pw_manager.add_password_to_vault(identifier, name, password)
        # Fetch an entry from the vault
        elif input_arg == 4:
            print("Fetching password")
            record_name = input("Please enter the record name:")
            pw_manager.fetch_password_from_vault(record_name)
        else:
            print("Exiting...")
            break