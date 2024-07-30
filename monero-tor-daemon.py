import os
import subprocess
import time
import requests
import secrets
import string

# Define paths and configuration details
torrc_path = os.path.join(os.getcwd(), "torrc")
ssl_key_path = "monero_ssl_key.pem" # chmod 600
ssl_cert_path = "monero_ssl_cert.pem"
ssl_key_path = "monero_ssl_key.pem"
hidden_service_dir = os.path.join(os.getcwd(), "monero_service")
daemon_address = "127.0.0.1:18081"
daemon_port = 18081
rpc_bind_port = 18089
blockchain_location = os.path.join(os.getcwd(), "monero_blockchain")
monerod_log_file = os.path.join(os.getcwd(), "monerod.log")
tor_user = "tor"
tor_port = 9250
# tor_data_dir = "tor_data"

# Generate a random password
def generate_and_save_password():
    if not os.path.exists(".env"):
        password_length = 512
        password_characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(password_characters) for _ in range(password_length))

        # Save the password to .env file
        env_file_path = os.path.join(os.getcwd(), ".env")
        with open(env_file_path, 'w') as file:
            file.write(f"RPC_PASSWORD={password}\n")

        print("Password has been generated and saved to .env file.")
    else:
        print(".env file already exists. Skipping password generation.")
        
#User {tor_user}
# Function to update torrc file
#DataDirectory {tor_data_dir}
def update_torrc():
    if not os.path.exists(torrc_path) or os.stat(torrc_path).st_size == 0:
        torrc_content = f"""
            SOCKSPort {tor_port}
            HiddenServiceDir {hidden_service_dir}
            HiddenServicePort {daemon_port} {daemon_address}
            HiddenServicePort {rpc_bind_port} 127.0.0.1:{rpc_bind_port}
        """
        with open(torrc_path, 'a') as file:
            file.write(torrc_content)

# Create a custom systemd service file for tor
def create_tor_service_file():
    tor_service_file_path = os.path.join(os.getcwd(), "monero-tor-daemon.service")
    tor_service_content = f"""
                            [Unit]
                            Description=Anonymizing Overlay Network for monero-tor-daemon
                            After=network.target nss-lookup.target

                            [Service]
                            Type=simple
                            ExecStart=/usr/bin/tor -f {torrc_path} --quiet
                            ExecReload=/bin/kill -HUP $MAINPID
                            KillSignal=SIGINT
                            TimeoutStartSec=60
                            TimeoutStopSec=30
                            Restart=always
                            RestartSec=60

                            [Install]
                            WantedBy=multi-user.target
                            """
    if not os.path.exists(tor_service_file_path):
        with open(tor_service_file_path, 'w') as file:
            file.write(tor_service_content)
        print("Custom systemd service file for tor has been created.")
        with open("monero-tor-daemon.service", 'w') as file:
            file.write(tor_service_content)
        
        subprocess.run(['sudo', 'cp', 'monero-tor-daemon.service', '/etc/systemd/system/monero-tor-daemon.service'])
        print("Custom systemd service file for tor has been copied to /etc/systemd/system/monero-tor-daemon.service")
        subprocess.run(["sudo", "systemctl", "enable", "monero-tor-daemon.service"]) # Enable the service
        print("Enabled the monero-tor-daemon.service")
        subprocess.run(["sudo", "systemctl", "start", "monero-tor-daemon.service"]) # Start the service
        print("Set owner for torrc file")
        subprocess.run(["sudo", "chown", f"{tor_user}:{tor_user}", torrc_path])
        print("Started the monero-tor-daemon.service")
        os.remove("monero-tor-daemon.service")
        print("Removed temporary file monero-tor-daemon.service")
    else:
        print("Custom systemd service file for tor already exists.")

# https://getmonero.dev/interacting/monero-wallet-rpc.html

# Function to create a custom systemd service file for monerod
def create_monerod_service_file():
    generate_and_save_password()
    onion_address = get_onion_address()
    rpc_password = os.getenv("RPC_PASSWORD")
    monerod_service_file_path = os.path.join(os.getcwd(), "monerod-tor-daemon.service")
    monerod_service_content = f"""
    [Unit]
    Description=Monero Daemon
    After=network.target

    [Service]
    User=monero
    Group=monero
    StateDirectory=monero
    LogsDirectory=monero

    Type=simple
    ExecStart=/usr/bin/monerod
        --config-file /etc/monerod.conf \
        --non-interactive \
        --blockchain-location {blockchain_location} \
        --log-file {monerod_log_file}/monerod.log  \
        --anonymous-inbound {onion_address}:18083,{daemon_address} \
        --tx-proxy tor,127.0.0.1:9050 \

        
        
        

        --daemon-address {daemon_address} \
        --daemon-host <arg>
        --proxy <arg>
        --trusted-daemon \
        --password-file <arg>
        --daemon-port {daemon_port} \
        --daemon-login {user:pass} \
        --daemon-ssl <arg=autodetect) \
        --daemon-ssl-private-key \
        --daemon-ssl-certificate <arg>
        --daemon-ssl-ca-certificates <arg>
        --daemon-ssl-allowed-fingerprints <arg>
        --daemon-ssl-allow-any-cert
        --daemon-ssl-allow-chained
        
        --rpc-bind-port {rpc_bind_port} \
        --disable-rpc-login \
        --restricted-rpc \
        --rpc-bind-ip 127.0.0.1
        --rpc-ssl <arg=autodetect>
        --rpc-ssl-key {ssl_key_path} \
        --rpc-ssl-private-key <arg>
        --rpc-ssl-certificate {ssl_cert_path} \
        --rpc-ssl-ca-certificates <arg>
        --rpc-ssl-allowed-fingerprints <arg>
        --rpc-ssl-allow-chained
        --rpc-client-secret-key <arg>
        --rpc-restricted-bind-ip 127.0.0.1 \
        --rpc-login monero:{rpc_password} \

        

        --detach \
        
        --log-file <arg>
        --log-level <arg>
        --max-log-file-size <arg=104850000>
        --max-log-files <arg=50>

    StandardOutput=null
    StandardError=null

    Restart=always

    [Install]
    WantedBy=multi-user.target
    """
    if not os.path.exists(monerod_service_file_path):
        with open(monerod_service_file_path, 'w') as file:
            file.write(monerod_service_content)
        print("Custom systemd service file for monerod has been created.")
        with open("monerod-tor-daemon.service", 'w') as file:
            file.write(monerod_service_content)
        subprocess.run(['sudo', 'cp', 'monerod-tor-daemon.service', '/etc/systemd/system/monerod-tor-daemon.service'])
        print("Custom systemd service file for monerod has been copied to /etc/systemd/system/monerod-tor-daemon.service")
        os.remove("monerod-tor-daemon.service")
        print("Removed temporary file monerod-tor-daemon.service")

# Function to get the onion address
def get_onion_address():
    with open(os.path.join(hidden_service_dir, "hostname"), 'r') as file:
        onion_address = file.read().strip()
    return onion_address

# Function to restart Tor service
def restart_tor():
    subprocess.run(["sudo", "systemctl", "restart", "monero-tor-daemon.service"])
    

# Function to generate SSL certificates
def generate_ssl_certificates():
    if not os.path.exists(ssl_key_path) or not os.path.exists(ssl_cert_path):
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-out", ssl_key_path, "-pkeyopt", "rsa_keygen_bits:4096"])
        subprocess.run(["openssl", "req", "-new", "-key", ssl_key_path, "-out", "monero_ssl_csr.pem", "-subj", "/CN=monero"])
        subprocess.run(["openssl", "x509", "-req", "-days", "365", "-in", "monero_ssl_csr.pem", "-signkey", ssl_key_path, "-out", ssl_cert_path])
        os.remove("monero_ssl_csr.pem")

# Function to set SSL permissions
def set_ssl_permissions():
    subprocess.run(["chmod", "600", ssl_key_path])
    subprocess.run(["chmod", "600", ssl_cert_path])

# Function to start monerod
def start_monerod(onion_address, auth_cookie):
    monerod_command = [
        "./monerod",
        f"--anonymous-inbound {onion_address}:18083,{daemon_address}",
        "--tx-proxy tor,127.0.0.1:9050",
        f"--rpc-bind-port {rpc_bind_port}",
        f"--rpc-ssl-cert {ssl_cert_path}",
        f"--rpc-ssl-key {ssl_key_path}",
        f"--rpc-login monero:{auth_cookie}",
        f"--detach"
    ]
    subprocess.run(monerod_command)

# Function to start monero-wallet-cli
def start_monero_wallet_cli(onion_address, auth_cookie):
    monero_wallet_cli_command = [
        "./monero-wallet-cli",
        f"--daemon-address https://{onion_address}:{rpc_bind_port}",
        "--proxy 127.0.0.1:9050",
        f"--daemon-login monero:{auth_cookie}",
        "--trusted-daemon",
        f"--daemon-ssl-ca-file {ssl_cert_path}"
    ]
    subprocess.run(monero_wallet_cli_command)

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

# Main setup function
def setup_monero_with_tor_and_ssl():
    generate_ssl_certificates()
    set_ssl_permissions()
    create_tor_service_file()
    update_torrc()
    restart_tor()  # Wait for Tor to restart and set up the hidden service
    create_monerod_service_file()
    
    time.sleep(10)  # Wait for 10 seconds to allow Tor to restart
    check_tor_connection()  # Check if Tor has successfully connected to the network
    # onion_address = get_onion_address()
    

    # # Get the auth cookie (this part may vary based on how you set it up)
    # auth_cookie_path = os.path.join(hidden_service_dir, "authorized_clients/monero_auth.auth")
    # with open(auth_cookie_path, 'r') as file:
    #     auth_cookie = file.read().strip()

    # start_monerod(onion_address, auth_cookie)

    # while True:
    #     result = check_monero_daemon_connection()  # Fixed: Assign the result of the check to a variable
    #     time.sleep(60)  # Wait for 1 minute before checking again
    #     if result.get("result", {}).get("synchronized", False):
    #         break
    # start_monero_wallet_cli(onion_address, auth_cookie)
    

if __name__ == "__main__":
    setup_monero_with_tor_and_ssl()