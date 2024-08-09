import subprocess
import os

# Fetch all -- param data from /etc/systemd/system/monerod-tor-daemon-ssl.service
with open('/etc/systemd/system/monerod-tor-daemon-ssl.service', 'r') as file:
    service_data = file.read()

with open('/var/lib/tor/torrc_monero_tor_daemon_ssl', 'r') as file:
    torrc_data = file.read()

# Extract values from torrc file
torrc_params = {}
for line in torrc_data.split('\n'):
    line = line.strip()
    line = line.replace('\\', '').rstrip()
    try:
        param, value = line.split(' ')
        torrc_params[param] = value
    except ValueError:
        continue

# Extract values from monero service file
monerod_params = {}
for line in service_data.split('\n'):
    if '--' in line:
        line = line.lstrip()
        line = line.replace('\\', '').rstrip()
        try:
            param, value = line.split(' ')
            monerod_params[param] = value
        except ValueError:
            # Handle the ValueError here
            # For example, you can skip the line or set a default value
            continue

# Daemon address variables
# Change the daemon address to onion host name for remote usage.
daemon_address = '127.0.0.1'
daemon_host = ''

monero_data_dir = "/var/lib/monero"
monero_wallet_dir = '/home/legion/Documents/monero_wallet'

# Use the extracted from torrc parameters as needed
tor_ip = '127.0.0.1'
tor_port = torrc_params.get('SOCKSPort')
hidden_service_dir = torrc_params.get('HiddenServiceDir')
hidden_service_port = torrc_params.get('HiddenServicePort')

# Use the extracted from monerod parameters as needed
data_dir = monerod_params.get('--data-dir')
log_file = monerod_params.get('--log-file')
log_level = monerod_params.get('--log-level')
anonymous_inbound = monerod_params.get('--anonymous-inbound')
tx_proxy = monerod_params.get('--tx-proxy')
proxy = monerod_params.get('--proxy')
igd = monerod_params.get('--igd')
max_connections_per_ip = monerod_params.get('--max-connections-per-ip')
p2p_bind_ip = monerod_params.get('--p2p-bind-ip')
p2p_bind_port = monerod_params.get('--p2p-bind-port')
p2p_bind_ipv6_address = monerod_params.get('--p2p-bind-ipv6-address')
p2p_bind_ipv6_port = monerod_params.get('--p2p-bind-ipv6-port')
p2p_external_port = monerod_params.get('--p2p-external-port')
rpc_bind_ip = monerod_params.get('--rpc-bind-ip')
rpc_login = monerod_params.get('--rpc-login')
rpc_ssl = monerod_params.get('--rpc-ssl')
rpc_ssl_private_key = monerod_params.get('--rpc-ssl-private-key')
rpc_ssl_certificate = monerod_params.get('--rpc-ssl-certificate')
rpc_ssl_ca_certifcates = monerod_params.get('--rpc-ssl-ca-certificates')
rpc_ssl_allowed_fingerprints = monerod_params.get('--rpc-ssl-allowed-fingerprints')

# Print all the extracted parameters
# print(f"tor_port: {tor_port}")
# print(f"hidden_service_dir: {hidden_service_dir}")
# print(f"hidden_service_port: {hidden_service_port}")
# print(f"data_dir: {data_dir}")
# print(f"log_file: {log_file}")
# print(f"log_level: {log_level}")
# print(f"anonymous_inbound: {anonymous_inbound}")
# print(f"tx_proxy: {tx_proxy}")
# print(f"proxy: {proxy}")
# print(f"igd: {igd}")
# print(f"max_connections_per_ip: {max_connections_per_ip}")
# print(f"p2p_bind_ip: {p2p_bind_ip}")
# print(f"p2p_bind_port: {p2p_bind_port}")
# print(f"p2p_bind_ipv6_address: {p2p_bind_ipv6_address}")
# print(f"p2p_bind_ipv6_port: {p2p_bind_ipv6_port}")
# print(f"p2p_external_port: {p2p_external_port}")
# print(f"rpc_bind_ip: {rpc_bind_ip}")
# print(f"rpc_login: {rpc_login}")
# print(f"rpc_ssl: {rpc_ssl}")
# print(f"rpc_ssl_private_key: {rpc_ssl_private_key}")
# print(f"rpc_ssl_certificate: {rpc_ssl_certificate}")
# print(f"rpc_ssl_ca_certifcate: {rpc_ssl_ca_certifcate}")
# print(f"rpc_ssl_allowed_fingerprints: {rpc_ssl_allowed_fingerprints}")


# Run the monerod command with the extracted parameters
subprocess.run(['sudo', '-u', 'monero', 'monero-wallet-cli', '--proxy', f'{tor_ip}:{tor_port}', '--daemon-address', f'{daemon_address}', '--daemon-host', f'{daemon_host}', '--trusted-daemon', '--daemon-login', f'{rpc_login}', '--daemon-ssl', 'enabled', '--daemon-ssl-private-key', f'{rpc_ssl_private_key}', '--daemon-ssl-certificate', f'{rpc_ssl_certificate}', '--daemon-ssl-ca-certificates', f'{rpc_ssl_ca_certifcates}', '--daemon-ssl-allowed-fingerprints', f'{rpc_ssl_allowed_fingerprints}', '--log-file', f'{log_file}', '--log-level', f'{log_level}, --wallet-file', f'{data_dir}'])
print()