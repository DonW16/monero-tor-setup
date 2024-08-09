import subprocess
import os

def remove_changes():
    try:
        subprocess.run(['sudo', 'rm', '/var/lib/tor/torrc_monero_tor_daemon_ssl'])
        print("/var/lib/tor/torrc_monero_tor_daemon_ssl removed successfully.")
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
        print("systemd daemon reloaded successfully.")
        print("monerod-tor-daemon.service removed successfully.")
        subprocess.run(['sudo', 'systemctl', 'stop', 'monerod-tor-daemon-ssl.service'])
        print("Stop monerod-tor-daemon-ssl.service")
        subprocess.run(['sudo', 'systemctl', 'disable', 'monerod-tor-daemon-ssl.service'])
        print("monerod-tor-daemon-ssl.service disabled successfully")
        subprocess.run(['sudo', 'rm', '/etc/systemd/system/monerod-tor-daemon-ssl.service'])
        print("/etc/systemd/system/monerod-tor-daemon-ssl.service removed successfully.")
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
        print("systemd daemon reloaded successfully.")
        subprocess.run(['sudo', 'systemctl', 'stop', 'monero-tor-daemon-ssl.service'])
        print("Stop monerod-tor-daemon-ssl.service")
        subprocess.run(['sudo', 'systemctl', 'disable', 'monero-tor-daemon-ssl.service'])
        print("monerod-tor-daemon-ssl.service disabled successfully")
        subprocess.run(['sudo', 'rm', '/etc/systemd/system/monero-tor-daemon-ssl.service'])
        print("/etc/systemd/system/monero-tor-daemon-ssl.service removed successfully.")
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
        print("systemd daemon reloaded successfully.")
        subprocess.run(['sudo', 'rm', '-rf', '/var/lib/monero/ssl'])
        print("/var/lib/monero/ssl removed successfully.")
        subprocess.run(['sudo', 'rm', '-rf', '/var/lib/monero/monero_logs'])
        print("/var/lib/monero/monero_logs removed successfully.")
        subprocess.run(['sudo', 'rm', '-rf', '/var/lib/tor/monero_hidden_service'])
        print("monerod-tor-daemon-ssl.service removed successfully.")
        subprocess.run(['sudo', 'systemctl', 'reset-failed'])
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'])
    except Exception as e:
        print(f"Error removing monero daemon service: {str(e)}")

remove_changes()
