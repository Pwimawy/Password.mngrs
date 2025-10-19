import os
import json
import base64
import getpass
import secrets
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
except Exception:
    print("\nERROR: This script requires the 'cryptography' package.\nInstall it with: pip install cryptography\n")
    sys.exit(1)

VAULT_FILE = Path.home() / '.vault_py.dat'
META_FILE = Path.home() / '.vault_meta_py.json'

# DEFAULT CREDENTIALS
DEFAULT_USERNAME = 'admin'
DEFAULT_PASSWORD = 'admin'  # change this after first login

PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_banner():
    banner = r"""
    ____                                __  __  ___                
   / __ \__  ___      ______  _________/ / /  |/  /___  ____ ______
  / /_/ / / / / | /| / / __ \/ ___/ __  / / /|_/ / __ \/ __ `/ ___/
 / ____/ /_/ /| |/ |/ / /_/ / /  / /_/ / / /  / / / / / /_/ / /    
/_/    \__, / |__/|__/\____/_/   \__,_(_)_/  /_/_/ /_/\__, /_/     
      /____/                                         /____/         
    """
    print(f"{Colors.OKCYAN}{banner}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}Made by {Colors.BOLD}Pwimawy{Colors.ENDC}\n")


def init_vault():
    """Create a new vault with default admin credentials."""
    if VAULT_FILE.exists() or META_FILE.exists():
        return

    salt = secrets.token_bytes(16)
    key = derive_key(DEFAULT_PASSWORD + DEFAULT_USERNAME, salt)
    f = Fernet(key)

    data = {
        'users': {
            DEFAULT_USERNAME: {
                'note': 'Default admin - please change the password on first login.'
            }
        },
        'entries': {}
    }

    token = f.encrypt(json.dumps(data).encode('utf-8'))
    VAULT_FILE.write_bytes(token)
    META_FILE.write_text(json.dumps({'salt': base64.b64encode(salt).decode('utf-8')}))
    print(f"Initialized new vault at {VAULT_FILE}")
    print("Default credentials created:")
    print(f"  username: {DEFAULT_USERNAME}")
    print(f"  password: {DEFAULT_PASSWORD}")
    print("PLEASE change the default password after you log in.\n")


def load_meta():
    if not META_FILE.exists():
        return None
    raw = json.loads(META_FILE.read_text())
    return base64.b64decode(raw['salt'])


def load_vault(master_username: str, master_password: str):
    salt = load_meta()
    if salt is None:
        print('Vault not initialized. Run the program to initialize.')
        return None
    key = derive_key(master_password + master_username, salt)
    f = Fernet(key)
    try:
        token = VAULT_FILE.read_bytes()
        data = json.loads(f.decrypt(token).decode('utf-8'))
        return data, key
    except Exception as e:
        return None, None


def save_vault(data: dict, key: bytes):
    f = Fernet(key)
    token = f.encrypt(json.dumps(data).encode('utf-8'))
    VAULT_FILE.write_bytes(token)


def prompt_credentials():
    username = input('Master username: ').strip()
    password = getpass.getpass('Master password: ')
    return username, password


def main_menu():
    print(f"\n{Colors.HEADER}=== MENU ==={Colors.ENDC}")
    print(f"{Colors.OKCYAN}1){Colors.ENDC} Add entry")
    print(f"{Colors.OKCYAN}2){Colors.ENDC} View entry")
    print(f"{Colors.OKCYAN}3){Colors.ENDC} List entries")
    print(f"{Colors.OKCYAN}4){Colors.ENDC} Update entry")
    print(f"{Colors.OKCYAN}5){Colors.ENDC} Delete entry")
    print(f"{Colors.OKCYAN}6){Colors.ENDC} Change master password")
    print(f"{Colors.OKCYAN}7){Colors.ENDC} Export vault (unencrypted JSON)")
    print(f"{Colors.OKCYAN}8){Colors.ENDC} Quit")



def add_entry(data):
    name = input('Entry name (site/app): ').strip()
    if not name:
        print('Name required.')
        return
    username = input('Username for this entry: ').strip()
    pwd = getpass.getpass('Password for this entry (leave blank to auto-generate): ')
    if not pwd:
        pwd = secrets.token_urlsafe(16)
        print('Generated password:', pwd)
    note = input('Notes (optional): ').strip()
    data['entries'][name] = {'username': username, 'password': pwd, 'note': note}
    print('Entry saved.')


def view_entry(data):
    name = input('Entry name to view: ').strip()
    entry = data['entries'].get(name)
    if not entry:
        print('Not found.')
        return
    print(f"\n{name}")
    print('  username:', entry['username'])
    print('  password:', entry['password'])
    print('  note:', entry.get('note',''))


def list_entries(data):
    names = sorted(data['entries'].keys())
    if not names:
        print('(no entries)')
        return
    print('\nEntries:')
    for n in names:
        print(' -', n)


def update_entry(data):
    name = input('Entry name to update: ').strip()
    entry = data['entries'].get(name)
    if not entry:
        print('Not found.')
        return
    print('Leave blank to keep current value')
    username = input(f"Username [{entry['username']}]: ").strip() or entry['username']
    pwd = getpass.getpass('Password (leave blank to keep): ')
    if not pwd:
        pwd = entry['password']
    note = input(f"Note [{entry.get('note','')}]: ").strip() or entry.get('note','')
    data['entries'][name] = {'username': username, 'password': pwd, 'note': note}
    print('Entry updated.')


def delete_entry(data):
    name = input('Entry name to delete: ').strip()
    if name in data['entries']:
        confirm = input(f'Confirm delete {name}? (y/N): ').strip().lower()
        if confirm == 'y':
            del data['entries'][name]
            print('Deleted.')
        else:
            print('Cancelled.')
    else:
        print('Not found.')


def change_master(data, old_key, old_username):
    print('\n--- Change master credentials ---')
    new_username = input('New master username: ').strip()
    new_password = getpass.getpass('New master password: ')
    if not new_username or not new_password:
        print('Username and password required.')
        return None
    # create new salt and derive new key
    new_salt = secrets.token_bytes(16)
    new_key = derive_key(new_password + new_username, new_salt)
    # save new meta
    META_FILE.write_text(json.dumps({'salt': base64.b64encode(new_salt).decode('utf-8')}))
    save_vault(data, new_key)
    print('Master credentials changed. Remember them!')
    return new_key, new_username


def export_vault_plain(data):
    out = Path.cwd() / 'vault_export.json'
    out.write_text(json.dumps(data, indent=2))
    print(f'Vault exported (UNENCRYPTED) to {out}. Keep it safe!')


def run(manager_username, manager_password):
    result = load_vault(manager_username, manager_password)
    if not result or result == (None, None):
        print('Invalid credentials or corrupted vault.')
        return
    data, key = result
    if not data or not key:
        print('Failed to decrypt vault: check username/password.')
        return

    while True:
        main_menu()
        choice = input('Choose: ').strip()
        if choice == '1':
            add_entry(data)
            save_vault(data, key)
        elif choice == '2':
            view_entry(data)
        elif choice == '3':
            list_entries(data)
        elif choice == '4':
            update_entry(data)
            save_vault(data, key)
        elif choice == '5':
            delete_entry(data)
            save_vault(data, key)
        elif choice == '6':
            res = change_master(data, key, manager_username)
            if res:
                key, manager_username = res
        elif choice == '7':
            export_vault_plain(data)
        elif choice == '8':
            print('Goodbye')
            break
        else:
            print('Invalid')


if __name__ == '__main__':
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    init_vault()
    print(f"{Colors.OKBLUE}Log in to unlock your vault{Colors.ENDC}")
    u, p = prompt_credentials()
    run(u, p)

