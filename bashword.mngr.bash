VAULT_FILE="$HOME/.vault_bash.dat"
SALT_FILE="$HOME/.vault_salt"
META_FILE="$HOME/.vault_meta"

# DEFAULT CREDENTIALS
DEFAULT_USERNAME="admin"
DEFAULT_PASSWORD="admin"  # change this after first login

CYAN="\033[96m"
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
BOLD="\033[1m"
RESET="\033[0m"

print_banner() {
cat << "EOF"
    ____             __                           __  __  ___                
   / __ )____ ______/ /_ _      ______  _________/ / /  |/  /___  ____ ______
  / __  / __ `/ ___/ __ \ | /| / / __ \/ ___/ __  / / /|_/ / __ \/ __ `/ ___/
 / /_/ / /_/ (__  ) / / / |/ |/ / /_/ / /  / /_/ / / /  / / / / / /_/ / /    
/_____/\__,_/____/_/ /_/|__/|__/\____/_/   \__,_(_)_/  /_/_/ /_/\__, /_/     
                                                               /____/      
EOF
echo -e "${GREEN}Made by ${BOLD}Pwimawy${RESET}\n"
}

init_vault() {
    if [[ -f "$VAULT_FILE" ]]; then
        return
    fi
    echo "Initializing new vault..."
    openssl rand -base64 16 > "$SALT_FILE"
    echo "{\"users\": {\"$DEFAULT_USERNAME\": \"Default admin\"}, \"entries\": {}}" > temp_vault.json
    encrypt_vault "$DEFAULT_PASSWORD$DEFAULT_USERNAME"
    echo "Vault initialized with default credentials:"
    echo "  Username: $DEFAULT_USERNAME"
    echo "  Password: $DEFAULT_PASSWORD"
    echo "Please change it after logging in!"
    rm -f temp_vault.json
}

derive_key() {
    local password="$1"
    local salt
    salt=$(cat "$SALT_FILE")
    echo -n "$password" | openssl enc -pbkdf2 -aes-256-cbc -md sha256 -iter 200000 -k "$password" -nosalt -P 2>/dev/null | grep key | awk '{print $2}'
}

encrypt_vault() {
    local password="$1"
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in temp_vault.json -out "$VAULT_FILE" -k "$password"
}

decrypt_vault() {
    local password="$1"
    openssl enc -aes-256-cbc -d -pbkdf2 -iter 200000 -in "$VAULT_FILE" -out temp_vault.json -k "$password" 2>/dev/null
    return $?
}

prompt_login() {
    echo -n "Master username: "
    read -r username
    echo -n "Master password: "
    read -s password
    echo
    decrypt_vault "$password$username"
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Invalid credentials or vault corrupted.${RESET}"
        rm -f temp_vault.json
        exit 1
    fi
}

add_entry() {
    echo -n "Entry name: "
    read -r name
    echo -n "Username: "
    read -r uname
    echo -n "Password (leave blank to auto-generate): "
    read -s pwd
    echo
    if [[ -z "$pwd" ]]; then
        pwd=$(openssl rand -base64 12)
        echo "Generated password: $pwd"
    fi
    echo -n "Note: "
    read -r note
    jq ".entries[\"$name\"] = {\"username\": \"$uname\", \"password\": \"$pwd\", \"note\": \"$note\"}" temp_vault.json > temp_new.json
    mv temp_new.json temp_vault.json
    echo -e "${GREEN}Entry added.${RESET}"
}

view_entry() {
    echo -n "Entry name: "
    read -r name
    jq -r ".entries[\"$name\"]" temp_vault.json
}

list_entries() {
    echo -e "${YELLOW}Vault entries:${RESET}"
    jq -r '.entries | keys[]' temp_vault.json
}

delete_entry() {
    echo -n "Entry name to delete: "
    read -r name
    jq "del(.entries[\"$name\"])" temp_vault.json > temp_new.json
    mv temp_new.json temp_vault.json
    echo -e "${RED}Deleted.${RESET}"
}

save_vault() {
    openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -in temp_vault.json -out "$VAULT_FILE" -k "$password$username"
    echo -e "${GREEN}Vault saved.${RESET}"
}

main_menu() {
    while true; do
        echo -e "\n${CYAN}=== MENU ===${RESET}"
        echo "1) Add entry"
        echo "2) View entry"
        echo "3) List entries"
        echo "4) Delete entry"
        echo "5) Quit"
        echo -n "Choose: "
        read -r choice
        case $choice in
            1) add_entry; save_vault ;;
            2) view_entry ;;
            3) list_entries ;;
            4) delete_entry; save_vault ;;
            5) rm -f temp_vault.json; echo "Goodbye!"; exit 0 ;;
            *) echo "Invalid." ;;
        esac
    done
}

clear
print_banner
init_vault
prompt_login
main_menu
