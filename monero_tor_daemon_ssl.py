import os
import subprocess
import base64
import time
import re
import sys
import requests
import secrets
import string
import nacl.public

# Define paths and configuration details
if os.geteuid() != 0:
    print("Please run the script as root or with sudo.")
    sys.exit(1)

# Tor configuration details and paths.
torrc_monero_tor_daemon_file = "/var/lib/tor/torrc_monero_tor_daemon_ssl"
torrc_data_dir = "/var/lib/tor"

hidden_service_dir = "/var/lib/tor/monero_hidden_service"
authorized_clients_dir = f"{hidden_service_dir}/authorized_clients"
client_onion_auth_dir = f"{hidden_service_dir}/tor_client_auth"
x25519_dir = f"{hidden_service_dir}/x25519_keys"
tor_user = "tor"
tor_ip = "127.0.0.1"
tor_port = 9250

monero_data_dir = "/var/lib/monero"
monero_ssl_dir = f"{monero_data_dir}/ssl"
#monero_blockchain_dir = f"{monero_data_dir}/monero_blockchain"
monero_blockchain_dir = f"/run/media/legion/4tb_btrfs/Monero blockchain"

tx_proxy_max_connections = 100
anonymous_inbound_max_connections = 100
max_connections_per_ip = 100

ssl_key_path = f"{monero_ssl_dir}/monero_ssl_key.pem"
ssl_cert_path = f"{monero_ssl_dir}/monero_ssl_cert.pem"
ssl_key_crt = f"{monero_ssl_dir}/monero_ssl_csr.pem"

p2p_address = "127.0.0.1"
p2p_address_ipv6 = "::1"
p2p_port = 18080

daemon_address = "127.0.0.1"
daemon_port = 18081
rpc_bind_ip = "127.0.0.1"
rpc_bind_port = 18089
blockchain_location = f"{monero_data_dir}/monero_blockchain"
monerod_log_file = f"{monero_data_dir}/monero_logs/monerod.log"

# Generate x25519 generated key
def generate_x25519_key():
    # Create x25519 folder if it does not exist
    if not os.path.exists(x25519_dir):
        subprocess.run(["sudo", "-u", "tor", "mkdir", "-p", "-m", "700", x25519_dir])
    else:
        print(f"{x25519_dir} directory already exists.")

    def key_str(key):
        # bytes to base 32
        key_bytes = bytes(key)
        key_b32 = base64.b32encode(key_bytes)
        # strip trailing ====
        assert key_b32[-4:] == b'===='
        key_b32 = key_b32[:-4]
        # change from b'ASDF' to ASDF
        s = key_b32.decode('utf-8')
        return s

    priv_key = nacl.public.PrivateKey.generate()
    pub_key = priv_key.public_key

    # Save the keys to files if they don't already exist
    pub_key_path = f"{x25519_dir}/x25519.pub"
    priv_key_path = f"{x25519_dir}/x25519.key"
    if not os.path.exists(pub_key_path):
        with open(pub_key_path, 'w') as file:
            file.write(key_str(pub_key))
    else:
        print(f"x25519 Public key {pub_key_path} already exists. Skipping public key generation.")
    if not os.path.exists(priv_key_path):
        with open(priv_key_path, 'w') as file:
            file.write(key_str(priv_key))
    else:
        print(f"x25519 Private key {priv_key_path} already exists. Skipping private key generation.")
    
    print(f"Changing owner of {x25519_dir} to tor user for newly created keys.")
    subprocess.run(["sudo", "chown", "-R", f"{tor_user}:{tor_user}", x25519_dir])

# Function to get the onion address
def get_onion_address():
    with open(os.path.join(hidden_service_dir, "hostname"), 'r') as file:
        onion_address = file.read().strip()
    return onion_address

# Generate a random password
def generate_and_save_password():
    if not os.path.exists(".env"):
        password_length = 1024
        password_characters = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(password_characters) for _ in range(password_length))

        # Save the password to .env file
        env_file_path = os.path.join(os.getcwd(), ".env")
        with open(env_file_path, 'w') as file:
            file.write(f"RPC_PASSWORD={password}\n")

        print("Daemon RPC password has been generated and saved to .env file.")
    else:
        print(".env file already exists. Skipping password generation.")

# Function to update torrc file
def update_torrc():
    print(f"Creating {torrc_monero_tor_daemon_file}...")
    if not os.path.exists(torrc_monero_tor_daemon_file) or os.stat(torrc_monero_tor_daemon_file).st_size == 0:
        torrc_content = f"""SOCKSPort {tor_port}
HiddenServiceDir {hidden_service_dir}
HiddenServicePort {daemon_port} {daemon_address}:{daemon_port}
HiddenServicePort {rpc_bind_port} 127.0.0.1:{rpc_bind_port}
HiddenServiceVersion 3
ClientOnionAuthDir {client_onion_auth_dir}
"""
        with open(torrc_monero_tor_daemon_file, 'a') as file:
            file.write(torrc_content)

    if not os.path.exists(torrc_monero_tor_daemon_file):
        print(f"torrc file has been created.")
        subprocess.run(["sudo", "cp", torrc_monero_tor_daemon_file, torrc_monero_tor_daemon_file])
        print(f"torrc file has been copied to {torrc_data_dir}.")
        subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", torrc_monero_tor_daemon_file])
        print(f"Owner for file {torrc_monero_tor_daemon_file} been changed to tor user.")
        os.remove(torrc_monero_tor_daemon_file)
        print("Removed temporary torrc file.")
    else:
        print(f"{torrc_monero_tor_daemon_file} already exists.")

def setup_tor_client_auth_folder():
    # Copy torrc to tor_data_dir and change owner to tor user
    tor_data_torrc_monero_tor_daemon_file_file = torrc_data_dir
    if not os.path.exists(client_onion_auth_dir):
        subprocess.run(["sudo", "-u", "tor", "mkdir", "-m", "700", client_onion_auth_dir])
        print(f"Created {client_onion_auth_dir} directory.")

    else:
        print(f"{client_onion_auth_dir} directory already exists.")

    if not os.path.exists(authorized_clients_dir):
        subprocess.run(["sudo", "-u", "tor", "mkdir", "-m", "700", authorized_clients_dir])
        print(f"Created {authorized_clients_dir} directory.")

    else:
        print(f"{authorized_clients_dir} directory already exists.")

# Function to setup tor client auth we will use server side client authentication because the hidden service is running on the same machine.
# to do use tor --keygen to generate keys
# to do set least privileged permissions for files
def setup_tor_client_auth(): 
    print(f"Reading x25519 {x25519_dir} public key...")
    with open(os.path.join(x25519_dir, "x25519.pub"), 'r') as file:
        pub_key = file.read().strip()
        name = pub_key.split(':')[0]
        authorized_clients_filename = name
    
    server_side_authorized_clients_file = os.path.join(authorized_clients_dir, authorized_clients_filename + ".auth")
    client_side_authorized_clients_file = os.path.join(client_onion_auth_dir, authorized_clients_filename + ".auth_private")
    
    print(f"Creating server side authorized clients file: {server_side_authorized_clients_file}")
    if not os.path.exists(server_side_authorized_clients_file):
        print(f"Reading x25519 {x25519_dir} private key...")
        with open(os.path.join(x25519_dir, "x25519.key"), 'r') as file:
            priv_key = file.read().strip()

        print(f"Creating {server_side_authorized_clients_file}...")
        with open(server_side_authorized_clients_file, 'w') as file:
            server_side_authorized_clients_file_content = f"{pub_key}:x25519:{pub_key}"
            file.write(server_side_authorized_clients_file_content)
            print(f"Authorized server side clients file {server_side_authorized_clients_file} has been created.")
        print(f"Changing owner of {server_side_authorized_clients_file} to tor user.")
        subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", server_side_authorized_clients_file])
    else:
        print(f"Authorized clients file {server_side_authorized_clients_file} already exists.")

    print(f"Creating client side authorized clients file: {client_side_authorized_clients_file}")
    if not os.path.exists(client_side_authorized_clients_file):
            print(f"Reading x25519 {client_side_authorized_clients_file} private key...")
            with open(os.path.join(x25519_dir, "x25519.key"), 'r') as file:
                priv_key = file.read().strip()

            print(f"Creating {client_side_authorized_clients_file}...")
            with open(client_side_authorized_clients_file, 'w') as file:
                onion_address = get_onion_address()
                client_side_authorized_clients_file_content = f"{onion_address}:{pub_key}:x25519:{priv_key}"
                file.write(client_side_authorized_clients_file_content)
                print(f"Authorized clients file {client_side_authorized_clients_file} has been created.")
            print("Changing owner of authorized clients file to tor user.")
            subprocess.run(["sudo", "chown", "-R", f"{tor_user}:{tor_user}", client_side_authorized_clients_file])
    else:
        print(f"Authorized clients file {client_side_authorized_clients_file} already exists.")
    
    print("Changing owner of authorized_clients directory to tor user.")
    subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", client_onion_auth_dir])
    print("Changing owner of tor_client_auth file to tor user.")
    subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", client_onion_auth_dir])
    print("Client authorization setup complete.")

# Create a custom systemd service file for tor
def create_tor_service_file():
    setup_tor_client_auth_folder()
    tor_service_file_path = os.path.join(os.getcwd(), "monero-tor-daemon-ssl.service")
    tor_service_content = f"""[Unit]
Description=Anonymizing Overlay Network for monero-tor-daemon-ssl
After=network.target nss-lookup.target

[Service]
Type=notify
ExecStartPre=/usr/bin/tor -f '{torrc_monero_tor_daemon_file}' --verify-config
ExecStart=/usr/bin/tor -f '{torrc_monero_tor_daemon_file}'
ExecReload=/bin/kill -HUP $MAINPID
User=tor
Group=tor
KillSignal=SIGINT
TimeoutSec=60
Restart=on-failure
WatchdogSec=1min
LimitNOFILE=32768

# Hardening
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=full
ReadOnlyDirectories=/
ReadWriteDirectories=-/var/lib/tor
ReadWriteDirectories=-/var/log/tor
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH CAP_KILL

[Install]
WantedBy=multi-user.target
"""
    if not os.path.exists(tor_service_file_path):
        with open(tor_service_file_path, 'w') as file:
            file.write(tor_service_content)
            print(f"Custom systemd service file {tor_service_file_path} for tor has been created.")

        print(f"Change {torrc_monero_tor_daemon_file} to tor user")
        subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", torrc_monero_tor_daemon_file])
        
        print(f"Custom systemd service file for tor has been copied to /etc/systemd/system/monero-tor-daemon-ssl.service")
        subprocess.run(['sudo', 'cp', f'{tor_service_file_path}', f'/etc/systemd/system/monero-tor-daemon-ssl.service'])
        
        print("Enabled the monero-tor-daemon-ssl.service")
        subprocess.run(["sudo", "systemctl", "enable", "monero-tor-daemon-ssl.service"]) # Enable the service

        print(f"Change {hidden_service_dir} to tor user")
        subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", hidden_service_dir])

        print(f"Changing {hidden_service_dir} to 700 chmod")
        subprocess.run(["sudo", "chmod", "700", hidden_service_dir])

        print("Started the monero-tor-daemon-ssl.service")
        subprocess.run(["sudo", "systemctl", "start", "monero-tor-daemon-ssl.service"]) # Start the service
        
        print("Removed temporary file monero-tor-daemon-ssl.service")
        os.remove("monero-tor-daemon-ssl.service") 
    else:
        print("Custom systemd service file for tor already exists.")

# Function to restart Tor service
def restart_tor():
    print("Restarting tor service...")
    subprocess.run(["sudo", "systemctl", "restart", "monero-tor-daemon-ssl.service"])

# Function to generate SSL certificates
# To do use monero-gen-ssl-cert to generate certs
def generate_ssl_certificates():
    print(f"Creating {monero_ssl_dir} directory...")
    if not os.path.exists(monero_ssl_dir):
        subprocess.run(["sudo", "-u", "monero", "mkdir", "-p", monero_ssl_dir])
        if not os.path.exists(ssl_key_path) or not os.path.exists(ssl_cert_path):
            result = subprocess.run(["sudo", "-u", "monero", "monero-gen-ssl-cert", f"--certificate-filename", f"{ssl_cert_path}", f"--private-key-filename", f"{ssl_key_path}"],
                                     capture_output=True,
                                     text=True)
            
            output = result.stdout
           
            # Regular expression to match the SHA-256 fingerprint
            fingerprint_pattern = r"SHA-256 Fingerprint: ([A-F0-9:]+)"

            # Search for the fingerprint in the output
            match = re.search(fingerprint_pattern, output)

            if match:
                sha256_fingerprint = match.group(1)
                return sha256_fingerprint
            else:
                print("SHA-256 Fingerprint not found.")
            print(f"SSL certificates have been generated in {monero_ssl_dir}.")
    else:
        print(f"{monero_ssl_dir} directory already exists.")

# Function to create a custom systemd service file for monerod
# to do hardening options for monerod systemd service
def create_monerod_service_file():
    # https://getmonero.dev/interacting/monero-wallet-rpc.html
    generate_and_save_password()
    ssl_fingerprint = generate_ssl_certificates()
    onion_address = get_onion_address()

    rpc_password = os.getenv("RPC_PASSWORD")
    monerod_service_file_path = os.path.join(os.getcwd(), "monerod-tor-daemon-ssl.service")
    monerod_service_content = f"""[Unit]
Description=Monero Daemon monerod-tor-daemon-ssl
After=network.target

[Service]
User=monero
Group=monero
StateDirectory=monero
LogsDirectory=monero

# Hardening copied from tor service and modified for monero
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=full
ReadOnlyDirectories=/
ReadWriteDirectories=-/var/lib/monero
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH CAP_KILL

Type=simple
ExecStart=/usr/bin/monerod \\
    --non-interactive \\
    --data-dir {blockchain_location} \\
    --log-file {monerod_log_file} \\
    --log-level 2 \\
    --anonymous-inbound {onion_address}:{daemon_port},{daemon_address}:{daemon_port},{anonymous_inbound_max_connections} \\
    --tx-proxy tor,{tor_ip}:{tor_port},{tx_proxy_max_connections} \\
    --proxy {tor_ip}:{tor_port} \\
    --hide-my-port \\
    --no-igd \\
    --igd disabled \\
    --pad-transactions \\
    --max-connections-per-ip {max_connections_per_ip} \\
    --p2p-bind-ip {p2p_address} \\
    --p2p-bind-port {p2p_port} \\
    --p2p-bind-ipv6-address {p2p_address_ipv6} \\
    --p2p-bind-port-ipv6 {p2p_port} \\
    --p2p-external-port {p2p_port} \\
    --rpc-bind-port {rpc_bind_port} \\
    --rpc-bind-ip {rpc_bind_ip} \\
    --rpc-login monero:{rpc_password} \\
    --rpc-ssl enabled \\
    --rpc-ssl-private-key {ssl_key_path} \\
    --rpc-ssl-certificate {ssl_cert_path} \\
    --rpc-ssl-ca-certificates {ssl_cert_path} \\
    --rpc-ssl-allowed-fingerprints {ssl_fingerprint} \\
    --rpc-ssl-allow-chained \\
    --detach

StandardOutput=null
StandardError=null

Restart=always

[Install]
WantedBy=multi-user.target
"""
    if not os.path.exists(monerod_service_file_path):
        with open(monerod_service_file_path, 'w') as file:
            file.write(monerod_service_content)
            print(f"Systemd service {monerod_service_file_path} for monerod has been created.")
        print(f"Systemd service {monerod_service_file_path} for monerod has been copied to /etc/systemd/system/monerod-tor-daemon-ssl.service")
        subprocess.run(['sudo', 'cp', f'{monerod_service_file_path}', '/etc/systemd/system/monerod-tor-daemon-ssl.service'])
        print(f"Enable /etc/systemd/system/monerod-tor-daemon-ssl.service")
        subprocess.run(["sudo", "systemctl", "enable", "monerod-tor-daemon-ssl.service"])
        print(f"Start /etc/systemd/system/monerod-tor-daemon-ssl.service")
        subprocess.run(["sudo", "systemctl", "start", "monerod-tor-daemon-ssl.service"])
        print(f"Remove temporary file {monerod_service_file_path}")
        os.remove("monerod-tor-daemon-ssl.service")
        print("Removed temporary file monerod-tor-daemon-ssl.service")
        subprocess.run(["sudo", "systemctl", "status", "monero-tor-daemon-ssl.service"])
        subprocess.run(["sudo", "systemctl", "status", "monerod-tor-daemon-ssl.service"])

# Function to restart Tor service
def restart_tor():
    print("Restarting monero-tor-daemon-ssl.service ...")
    subprocess.run(["sudo", "systemctl", "restart", "monero-tor-daemon-ssl.service"])   

# Main setup function
def setup_monero_with_tor_and_ssl():
    generate_x25519_key()
    update_torrc()
    create_tor_service_file()
    restart_tor()
    setup_tor_client_auth()
    create_monerod_service_file()   

# Function to check Tor connection
def check_tor_connection():
    session = requests.session()
    session.proxies = {
        'http': 'socks5h://localhost:9050',
        'https': 'socks5h://localhost:9050'
    }
    
    while True:
        try:
            response = session.get("https://check.torproject.org/api/ip")
            if response.status_code == 200 and response.json().get("IsTor") == True:
                print("Tor has successfully connected to the network.")
                break
            else:
                print("Tor is not yet connected to the network. Retrying in 10 seconds...")
                time.sleep(10)
        except requests.exceptions.RequestException as e:
            print("Error occurred while checking Tor connection:", str(e))
            print("Retrying in 10 seconds...")
            time.sleep(10)

# Function to check Monero daemon connection
def check_monero_daemon_connection():
    url = "http://localhost:18081/json_rpc"
    headers = {'content-type': 'application/json'}
    payload = {
        "jsonrpc": "2.0",
        "id": "0",
        "method": "get_info"
    }
    
    response = requests.post(url, json=payload, headers=headers)
    result = response.json()
    
    result = check_monero_daemon_connection()
    if result.get("result", {}).get("synchronized", False):
        print("The Monero daemon is correctly connected and synchronized with the network.")
    else:
        print("The Monero daemon is not correctly connected or not yet synchronized with the network.")


if __name__ == "__main__":
    setup_monero_with_tor_and_ssl()