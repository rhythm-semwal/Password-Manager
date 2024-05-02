# Password-Manager

This Password Manager is a command-line tool written in Python for securely managing passwords in encrypted vaults. The script allows users to create new password vaults, sign in to existing vaults, add passwords to vaults, fetch passwords from vaults, and more.

### Usage
The Password Manager offers the following functionalities:

1. Create a New Password Vault:
Creates a new encrypted password vault with a specified name and master password.
2. Sign In to a Password Vault:
Signs in to an existing password vault using the vault name and master password.
3. Add a Password to a Vault:
Adds a new entry (username and password) to the currently signed-in vault.
4. Fetch a Password from a Vault:
Retrieves and displays a password from the currently signed-in vault.
## Setup

Clone the Repository:
```bash
git clone https://github.com/rhythm-semwal/Password-Manager.git
```
Navigate to the Project Directory:
```bash
cd Password-Manager
```
Install Required Dependencies:
```bash
pip install -r requirements.txt
```
Run the Password Manager:
```bash
python3 main.py
```

### A simple password manager script that can be executed using the `ccpm` command.

### Setup

1. **Clone Repository:**
   ```bash
   git clone "https://github.com/rhythm-semwal/Password-Manager.git"
   
2. Make Script Executable:

```bash
cd Password-Manager
```

```bash
chmod +x main.py
```

```bash
mkdir -p ~/bin
```

```bash
mv main.py ~/bin/ccpm
```

```bash
export PATH="$HOME/bin:$PATH"
```

```bash
source ~/.bashrc  # or ~/.bash_profile, ~/.zshrc, etc.
```

```bash
chmod +x ccpm
```

```bash
ccpm
```
