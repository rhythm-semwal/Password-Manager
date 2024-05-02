from import_file import *


class VaultUtility:
    @staticmethod
    def load_vault(vault_name):
        vault_filename = f'{vault_name}.json'
        if os.path.exists(vault_filename):
            with open(vault_filename, 'r') as vault_file:
                current_vault = json.load(vault_file)
        else:
            current_vault = {}
            with open(vault_filename, 'w') as vault_file:
                json.dump(current_vault, vault_file)

        return current_vault

    @staticmethod
    def save_vault(vault_name, current_vault):
        vault_filename = f'{vault_name}.json'
        with open(vault_filename, 'w') as vault_file:
            json.dump(current_vault, vault_file, indent=4)
        print(f"Vault '{vault_name}' saved successfully.")
