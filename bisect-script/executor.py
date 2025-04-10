#!/usr/bin/env python3
# Purpose: Remote command execution tool supporting both SSH and Telnet
# Author: Merged from ssh.py and telnet.py

import argparse
import os
import subprocess
import sys
import time
import socket
import paramiko
import threading
import shlex
import telnetlib
import re

class RemoteExecutor:
    """Base class for remote execution functionality"""
    
    DEFAULT_PORT = None  # To be overridden by subclasses
    DEFAULT_LOG_DIR = "./logs"
    
    @staticmethod
    def wait_for_device(ip_address, max_wait=300):
        """Wait for the device to be reachable."""
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

        return True
    
    @staticmethod
    def wait_for_port(ip_address, port, service_name, max_wait=300):
        """Wait for a specific port to be open."""
        start_time = time.time()
        print(f"Waiting for {service_name} port {port} on {ip_address}...")
        
        while True:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip_address, port))
            sock.close()

            if result == 0:  # Port is open
                print(f"{service_name} port is ready")
                return True

            if time.time() - start_time >= max_wait:
                print(f"Timeout: {service_name} service not ready")
                return False
            time.sleep(5)
    
    @staticmethod
    def create_log_file(log_dir, ip_address, protocol="remote", suffix=""):
        """Create the log directory if it doesn't exist and return log file path."""
        try:
            os.makedirs(log_dir, exist_ok=True)
            filename = f"{protocol}-{ip_address}{suffix}.log"
            log_path = os.path.join(log_dir, filename)
            return log_path
        except Exception as e:
            print(f"Error creating log directory: {e}")
            exit(125)
    
    @staticmethod
    def read_log_file(log_path):
        """Read log file contents and return as string."""
        try:
            with open(log_path, "r") as f:
                return f.read()
        except Exception as e:
            return f"Could not read log file: {str(e)}"
    
    @classmethod
    def run_command(cls, ip, port=None, username=None, password=None, command=None, log_dir=None, **kwargs):
        """Base method for executing remote commands - to be implemented by subclasses"""
        # Use defaults if not specified
        port = port or cls.DEFAULT_PORT
        log_dir = log_dir or cls.DEFAULT_LOG_DIR
        
        # Create log path (subclasses should call this)
        protocol_name = cls.__name__.lower().replace('executor', '')
        log_path = cls.create_log_file(log_dir, ip, protocol_name)
        
        # Common pre-execution steps
        if not cls.wait_for_device(ip):
            return False, "Device not reachable", log_path
            
        if not cls.wait_for_port(ip, port, protocol_name.upper()):
            return False, f"{protocol_name.upper()} service not ready", log_path
            
        # Subclasses should implement their specific execution logic
        raise NotImplementedError("Subclasses must implement run_command")


class SSHExecutor(RemoteExecutor):
    """SSH remote execution functionality"""
    
    DEFAULT_PORT = 22

    @staticmethod
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

    @staticmethod
    def setup_ssh_client(ip, port, username, key_file=None, password=None, ssh_options=None):
        """Set up SSH client with appropriate authentication and options."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Parse and apply SSH options
        connect_kwargs = {}
        if ssh_options:
            connect_kwargs.update(SSHExecutor.parse_ssh_options(ssh_options))

        # Set default timeout if not specified in options
        if "timeout" not in connect_kwargs:
            connect_kwargs["timeout"] = 30
            
        connect_kwargs["port"] = port

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

    @staticmethod
    def execute_remote_ssh(
        ip, port, username, command, log_path, key_file=None, password=None, ssh_options=None
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
                client = SSHExecutor.setup_ssh_client(ip, port, username, key_file, password, ssh_options)

                # Open a log file
                with open(log_path, "w") as log_file:
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
    
    @classmethod
    def run_command(
        cls,
        ip,
        port=None,
        username=None,
        password=None,
        command=None,
        log_dir=None,
        key_file=None,
        ssh_options=None,
        **kwargs
    ):
        """
        Simplified function to run a command on a remote host via SSH.
        This function combines the individual steps and can be easily imported.
        """
        # Call parent class method for common setup
        log_dir = log_dir or cls.DEFAULT_LOG_DIR
        port = port or cls.DEFAULT_PORT
        
        # Create log file path
        ssh_log_path = cls.create_log_file(log_dir, ip, "ssh")
        
        # Common pre-execution checks
        if not cls.wait_for_device(ip):
            return False, "Device not reachable", ssh_log_path
            
        if not cls.wait_for_port(ip, port, "SSH"):
            return False, "SSH service not ready", ssh_log_path

        # Execute the command
        exit_code = cls.execute_remote_ssh(
            ip, port, username, command, ssh_log_path, key_file, password, ssh_options
        )

        # Read the log file contents to return
        log_content = cls.read_log_file(ssh_log_path)

        return exit_code == 0, log_content, ssh_log_path


class TelnetExecutor(RemoteExecutor):
    """Telnet remote execution functionality"""
    
    DEFAULT_PORT = 23
    DEFAULT_PROMPT = "root@intel-x86-64:# "
    
    @staticmethod
    def telnet_login(tn, host, port, username, password, prompt_bytes):
        """Connect to the remote host and log in."""
        print(f"Connecting to {host}:{port}...")
        tn.read_until(b"login: ", timeout=10)
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ", timeout=10)
        tn.write(password.encode('ascii') + b"\n")
        tn.read_until(prompt_bytes, timeout=10)
        print(f"{host}: Login completed, received command prompt")
        return tn
    
    @staticmethod
    def send_telnet_command(tn, command, prompt_bytes, log_file, timeout=5):
        """Send a command to the telnet connection."""
        exit_code = 1
        try:
            tn.write(command.encode('ascii') + b"\n")
            response = tn.read_until(prompt_bytes, timeout).decode('ascii')
            log_file.write(response)

            if "Kernel panic" in response:
                return 1, True

            marker = f"EXITCODE_MARKER_{int(time.time())}"
            exit_cmd = f"echo '{marker}'$?'{marker}'".encode('ascii')
            tn.write(exit_cmd + b"\n")

            response = tn.read_until(prompt_bytes, timeout).decode('ascii')
            pattern = re.escape(marker) + r'\s*(\d+)\s*' + re.escape(marker)
            exit_code_match = re.search(pattern, response, re.DOTALL)

            if exit_code_match:
                exit_code = int(exit_code_match.group(1))
            return exit_code, False
        except Exception as e:
            print(f"Error sending command: {str(e)}")
            return 1, False
    
    @staticmethod
    def close_telnet(tn):
        """Close the telnet connection."""
        tn.write(b"exit\n")
        tn.close()
    
    @classmethod
    def run_command(
        cls,
        ip,
        port=None,
        username=None,
        password=None,
        command=None,
        log_dir=None,
        prompt_pattern=None,
        timeout=5,
        **kwargs
    ):
        """
        Run a command or script on a remote server via telnet.
        """
        # Use defaults if not specified
        port = port or cls.DEFAULT_PORT
        log_dir = log_dir or cls.DEFAULT_LOG_DIR
        prompt_pattern = prompt_pattern or cls.DEFAULT_PROMPT
        
        return cls.run_telnet_script(
            ip, port, username, password, command, log_dir, prompt_pattern, timeout
        )
    
    @classmethod
    def run_telnet_script(
        cls, 
        host, 
        port, 
        username, 
        password, 
        commands_script,
        log_dir=None, 
        prompt_pattern=None, 
        timeout=5
    ):
        """Connect to a remote server via telnet and execute multiple commands from a script."""
        log_dir = log_dir or cls.DEFAULT_LOG_DIR
        prompt_pattern = prompt_pattern or cls.DEFAULT_PROMPT
        
        telnet_log_path = cls.create_log_file(log_dir, host, "telnet")
        
        if not cls.wait_for_device(host):
            return False, "Device not reachable", telnet_log_path
            
        if not cls.wait_for_port(host, port, "Telnet"):
            return False, "Telnet service not ready", telnet_log_path
        
        try:
            # Convert the prompt pattern to bytes for telnetlib
            prompt_bytes = prompt_pattern.encode('ascii')
            
            # Connect to the server
            tn = telnetlib.Telnet(host, port, timeout=10)
            
            with open(telnet_log_path, "w") as log_file:
                # Login
                cls.telnet_login(tn, host, port, username, password, prompt_bytes)
                
                # Split the commands_script into individual commands
                commands = [cmd.strip() for cmd in commands_script.strip().split('\n') if cmd.strip()]
                
                # Execute each command and check exit code
                for cmd in commands:
                    print(f"\nExecuting: {cmd}")
                    
                    # Clear any pending output
                    tn.read_very_eager()
                    # Send the command
                    exit_code, is_reboot = cls.send_telnet_command(tn, cmd, prompt_bytes, log_file)
                    
                    if is_reboot:
                        log_file.write("Detected kernel panic or reboot\n")
                        print("Kernel panic, reading reboot log")
                        while True:
                            response = tn.read_until(prompt_bytes, 100).decode('ascii')
                            log_file.write(response)
                            if cls.wait_for_device(host, 2):
                                break
                        response = tn.read_until(prompt_bytes, 100).decode('ascii')
                        log_file.write(response)
                        print("Read all logs, attempting to reconnect")
                        cls.telnet_login(tn, host, port, username, password, prompt_bytes)
                        exit_code, is_reboot = cls.send_telnet_command(tn, "\n", prompt_bytes, log_file)
                        exit_code, is_reboot = cls.send_telnet_command(tn, "cat /proc/cmdline", prompt_bytes, log_file)

                        frame = sys._getframe(0)
                        print(f"Add your commands here {frame.f_code.co_filename}:{frame.f_lineno} to make sure the system reboot completely ")
                        if exit_code != 0:
                            break
                    elif exit_code != 0:
                        print(f"✗ ERROR: Command returned non-zero exit code: {exit_code}")
                        cls.close_telnet(tn)
                        
                        log_content = cls.read_log_file(telnet_log_path)
                        return False, log_content, telnet_log_path
                    else:
                        print("✓ Command executed successfully")
                
                print("\nAll commands completed successfully!")
                # Close connection
                cls.close_telnet(tn)
                
            log_content = cls.read_log_file(telnet_log_path)
                
            return True, log_content, telnet_log_path
                
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            with open(telnet_log_path, "a") as log_file:
                log_file.write(f"Error in telnet script execution: {e}\n")
            return False, str(e), telnet_log_path


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Reliable remote command execution tool (SSH and Telnet)"
    )
    parser.add_argument("-u", "--user", required=True, help="Username (required)")
    parser.add_argument("-i", "--ip", required=True, help="Device IP (required)")
    parser.add_argument(
        "-c", "--command", required=True, help="Command or script path to execute (required)"
    )
    parser.add_argument(
        "-l", "--log_dir", default="./logs", help="Log directory (default: ./logs)"
    )
    parser.add_argument(
        "-m", "--mode", choices=["ssh", "telnet"], default="ssh",
        help="Connection mode (ssh or telnet, default: ssh)"
    )
    parser.add_argument("-k", "--key_file", help="SSH private key path (optional)")
    parser.add_argument(
        "-p", "--password", help="Password for authentication (optional for ssh)"
    )
    parser.add_argument(
        "--port", type=int, help=f"Port number (default: 22 for SSH, 23 for Telnet)"
    )
    parser.add_argument(
        "--prompt", default="root@intel-x86-64:# ",
        help="Telnet prompt pattern (default: 'root@intel-x86-64:# ')"
    )
    parser.add_argument(
        "--script", action="store_true",
        help="Treat command as a multi-line script file"
    )

    args, unknown_args = parser.parse_known_args()

    # Mode-specific validation
    if args.mode == "ssh":
        if not args.key_file and not args.password:
            parser.error("SSH mode requires either key_file or password!")
    elif args.mode == "telnet":
        if not args.password:
            parser.error("Telnet mode requires a password!")

    return args, " ".join(unknown_args)


def main():
    """Main function to coordinate the script execution."""
    args, extra_options = parse_arguments()

    if args.script and os.path.isfile(args.command):
        try:
            with open(args.command, 'r') as f:
                args.command = f.read()
        except Exception as e:
            print(f"Error reading script file: {e}")
            exit(125)
    
    if args.mode == "ssh":
        executor = SSHExecutor
        # Prepare kwargs for SSH
        kwargs = {
            "key_file": args.key_file,
            "ssh_options": extra_options
        }
    else:  # telnet mode
        executor = TelnetExecutor
        # Check if command is a file path for script mode
                
        # Prepare kwargs for telnet
        kwargs = {
            "prompt_pattern": args.prompt,
            "is_script": args.script
        }
    
    # Execute the command using the appropriate executor
    success, log_content, log_path = executor.run_command(
        ip=args.ip,
        port=args.port,  # Default handling is now in the class
        username=args.user,
        password=args.password,
        command=args.command,
        log_dir=args.log_dir,
        **kwargs
    )
    
    exit(0 if success else 1)


if __name__ == "__main__":
    main()