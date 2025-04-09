#!/usr/bin/env python3
# Purpose: Reliable remote command execution tool
# How to use:
# 1. from remote import run_ssh_command
# 2. python3 ./remote_executor.py -u jchang1 -i jchang1-Meteor ...

import argparse
import os
import subprocess
import sys
import time
import socket
import paramiko
import threading
import shlex


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Reliable remote command execution tool"
    )
    parser.add_argument("-u", "--user", required=True, help="SSH username (required)")
    parser.add_argument("-i", "--ip", required=True, help="Device IP (required)")
    parser.add_argument(
        "-c", "--command", required=True, help="Command to execute (required)"
    )
    parser.add_argument(
        "-l", "--log_dir", required=True, help="Log directory (required)"
    )
    parser.add_argument("-k", "--key_file", help="SSH private key path (optional)")
    parser.add_argument(
        "-p",
        "--password",
        help="SSH password (optional, choose between key or password)",
    )
    # parser.add_argument('-o', '--ssh_options', action='append', help='Additional SSH client parameters (optional)')

    args, unknown_args = parser.parse_known_args()

    # Check if either key or password is provided
    if not args.key_file and not args.password:
        parser.error("Must provide either key_file or password!")

    return args, " ".join(unknown_args)


def create_log_directory(log_dir, ip_address):
    """Create the log directory if it doesn't exist and return log file path."""
    try:
        os.makedirs(log_dir, exist_ok=True)
        return os.path.join(log_dir, f"ssh-{ip_address}.log")
    except Exception as e:
        print(f"Error creating log directory: {e}")
        exit(125)


def wait_for_device(ip_address, max_wait=300):
    """Wait for the device to be reachable and SSH to be ready."""
    start_time = time.time()

    print(f"Waiting for device {ip_address} to come online...")

    # Wait for ping to succeed
    while True:
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_address],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            break
        except subprocess.CalledProcessError:
            if time.time() - start_time >= max_wait:
                print("Timeout: Device did not respond")
                return False
            time.sleep(5)

    # Wait for SSH port to be open
    start_time = time.time()
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, 22))
        sock.close()

        if result == 0:  # Port is open
            return True

        if time.time() - start_time >= max_wait:
            print("Timeout: SSH not ready")
            return False
        time.sleep(5)


def parse_ssh_options(options_string):
    """Parse SSH options string into a dictionary for paramiko."""
    if not options_string:
        return {}

    ssh_config = {}
    options = shlex.split(options_string)

    for i in range(0, len(options), 2):
        if i + 1 < len(options):
            key = options[i].lstrip("-")
            value = options[i + 1]

            # Map common SSH options to paramiko parameters
            if key == "o":
                # Handle -o option=value format
                option_parts = value.split("=", 1)
                if len(option_parts) == 2:
                    opt_name, opt_value = option_parts

                    # Map specific options to paramiko parameters
                    if opt_name == "ConnectTimeout":
                        ssh_config["timeout"] = float(opt_value)
                    elif opt_name == "Port":
                        ssh_config["port"] = int(opt_value)
                    elif opt_name == "StrictHostKeyChecking":
                        if opt_value.lower() == "no":
                            # This is handled by setting AutoAddPolicy
                            pass
            elif key == "p":
                ssh_config["port"] = int(value)
            # Add more mappings as needed

    return ssh_config


def setup_ssh_client(ip, username, key_file=None, password=None, ssh_options=None):
    """Set up SSH client with appropriate authentication and options."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Parse and apply SSH options
    connect_kwargs = {}
    if ssh_options:
        connect_kwargs.update(parse_ssh_options(ssh_options))

    # Set default timeout if not specified in options
    if "timeout" not in connect_kwargs:
        connect_kwargs["timeout"] = 30

    # Add authentication parameters
    if key_file:
        try:
            private_key = paramiko.RSAKey.from_private_key_file(
                key_file, password=password
            )
            connect_kwargs["pkey"] = private_key
        except Exception as e:
            print(f"Error with private key: {e}")
            raise
    elif password:
        connect_kwargs["password"] = password

    # Connect to the server
    try:
        client.connect(ip, username=username, **connect_kwargs)
        return client
    except Exception as e:
        print(f"SSH connection error: {e}")
        raise


def execute_remote(
    ip, username, command, log_path, key_file=None, password=None, ssh_options=None
):
    """Execute remote command with retry logic."""
    attempt = 0
    max_attempts = 1
    exit_code = 1  # Default error code if all attempts fail

    print(f"Execute command {command}")

    while attempt < max_attempts:
        print(f"Attempting to execute command (attempt {attempt+1})...")

        try:
            # Setup SSH client with proper authentication and options
            client = setup_ssh_client(ip, username, key_file, password, ssh_options)

            # Open a log file
            with open(log_path, "w") as log_file:
                # Request a pseudo-terminal (PTY)
                # transport = client.get_transport()
                # channel = transport.open_session()
                # channel.get_pty()

                # Prepare the command with debugging enabled
                # bash_wrapper = f"set -eo pipefail\nset -x\n{command}"
                # Modify the command to ensure trace and output are properly ordered
                bash_wrapper = f"""
set -eo pipefail
# Redirect both stdout and stderr to stdout to keep ordering
exec 2>&1
# Enable command tracing
set -x
{command}
"""

                # Start command execution
                stdin, stdout, stderr = client.exec_command(bash_wrapper)

                # Now we only need to read from stdout as stderr is redirected there
                for line in stdout:
                    log_file.write(line)
                    # print(line, end='')

                exit_code = stdout.channel.recv_exit_status()

                log_file.write(f"\nExit code: {exit_code}\n")

            if exit_code == 0:
                print("\nExecution successful")
                client.close()
                return 0
            else:
                print(f"\nExecution failed, exit code: {exit_code}")
                client.close()
                time.sleep(attempt * 10)
                attempt += 1

        except Exception as e:
            print(f"SSH connection error: {e}")
            with open(log_path, "a") as log_file:
                log_file.write(f"SSH connection error: {e}\n")
            time.sleep(attempt * 10)
            attempt += 1
            if "client" in locals():
                client.close()

    return exit_code


def run_ssh_command(
    ip,
    username,
    command,
    log_dir="./logs",
    key_file=None,
    password=None,
    ssh_options=None,
):
    """
    Simplified function to run a command on a remote host.
    This function combines the individual steps and can be easily imported.
    """
    # Create log directory and file
    ssh_log_path = create_log_directory(log_dir, ip)

    # Wait for device to be available
    if not wait_for_device(ip):
        return False, "Device not reachable", None

    # Execute the command
    exit_code = execute_remote(
        ip, username, command, ssh_log_path, key_file, password, ssh_options
    )

    # Read the log file contents to return
    try:
        with open(ssh_log_path, "r") as f:
            log_content = f.read()
    except:
        log_content = "Could not read log file"

    return exit_code == 0, log_content, ssh_log_path


def main():
    """Main function to coordinate the script execution."""
    args, ssh_options = parse_arguments()
    ssh_log_path = create_log_directory(args.log_dir, args.ip)

    if wait_for_device(args.ip):
        exit_code = execute_remote(
            args.ip,
            args.user,
            args.command,
            ssh_log_path,
            args.key_file,
            args.password,
            ssh_options,
        )
        exit(exit_code)
    else:
        exit(125)


if __name__ == "__main__":
    main()
