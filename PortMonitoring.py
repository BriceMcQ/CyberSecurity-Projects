
#Port Security Monitoring Tool#

import socket
import subprocess
import platform
import datetime
import logging

# Setup logging
log_file = f"port_security_log_{datetime.date.today()}.log"
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Define common ports and expected state
# You can edit or add specific ports relevant to your environment
EXPECTED_PORTS = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp"
}

def get_open_ports():
    """
    Use netstat to find all open ports on the system.
    Returns a dictionary of {port: protocol}
    """
    open_ports = {}
    try:
        if platform.system().lower() == "windows":
            cmd = "netstat -an"
        else:
            cmd = "sudo netstat -tunlp"

        output = subprocess.check_output(cmd, shell=True, text=True)

        for line in output.splitlines():
            if 'LISTEN' in line or 'ESTABLISHED' in line:
                parts = line.split()
                if platform.system().lower() == "windows":
                    address = parts[1]
                else:
                    address = parts[3]
                if ':' in address:
                    port = int(address.split(":")[-1])
                    open_ports[port] = parts[0]
    except Exception as e:
        logging.error(f"Error retrieving open ports: {e}")
    return open_ports

def check_ports():
    """
    Check open ports and compare them to the expected list.
    Logs if unexpected ports are found.
    """
    logging.info("Starting port check...")
    open_ports = get_open_ports()
    for port in open_ports:
        if port not in EXPECTED_PORTS:
            logging.warning(f"?? Unexpected open port detected: {port} ({open_ports[port]})")
        else:
            logging.info(f"? Expected port open: {port} ({EXPECTED_PORTS[port]})")

    logging.info("Port check complete.")

if __name__ == "__main__":
    check_ports()
