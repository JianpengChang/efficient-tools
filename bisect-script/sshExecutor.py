#!/usr/bin/env python3
import paramiko
import time
import re
import os
import subprocess
from typing import List, Tuple, Any


class SSHClient:
    """
    Object-oriented SSH client for connecting to servers and executing commands
    with comprehensive logging and result verification.
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str = None,
        key_filename: str = None,
        port: int = 22,
        log_dir: str = "",
        exit_on_fail = True,
    ):
        """
        Initialize SSH client with connection parameters

        Args:
            host: The server host or IP address
            username: SSH username
            password: SSH password (optional if using key-based auth)
            key_filename: Path to private key file (optional)
            port: SSH port (default 22)
            log_file: Path to log file (default: ssh_session.log)
        """
        self.host = host
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.port = port
        self.log_file = os.path.join(log_dir, f"ssh-{host}-{port}.log")
        self.client = None
        self.channel = None
        self.connected = False
        self.prompt = None
        self.exit_on_fail = exit_on_fail

        self.log = open(self.log_file, "a")

    def connect(self) -> bool:
        """
        Establish SSH connection to the server

        Returns:
            bool: True if connection successful, False otherwise
        """
        if not self._wait_for_device():
            print(f"device boot up failed")
            return False
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self._write_log(f"Connecting to {self.host}:{self.port}...")

            # Connect with either password or key file
            if self.key_filename:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_filename,
                )
            else:
                self.client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                )

            # Open interactive session
            self.channel = self.client.invoke_shell(
                term="vt100",  # Simple terminal type with minimal control sequences
                width=1000,  # Wide terminal to avoid line wrapping
                height=1000,  # Tall terminal to avoid scrolling issues
            )
            self._configure_terminal()

            self.channel.send(r'exec 2>&1 && PS1="\u@\H:$ "' + "\n")

            self._read_until_prompt()
            self.channel.send("\n")
            self.prompt = self._read_until_prompt().strip()

            self.connected = True
            self._write_log("Connection established successfully.")
            return True

        except Exception as e:
            self._write_log(f"Connection failed: {str(e)}")
            return False

    def close(self) -> None:
        """Close the SSH connection"""
        if self.client:
            self._write_log("Disconnecting from server...")
            self.client.close()
            self.connected = False
            self._write_log("Connection closed.")
        self.log.close()

    def _configure_terminal(self) -> None:
        """Configure shell to produce clean output without control sequences"""
        # Wait a moment for shell to initialize
        time.sleep(0.5)

        # Set of commands to configure a clean terminal environment
        terminal_setup_commands = [
            # Disable command echo
            "stty -echo",
            # Set TERM to a simple terminal type
            "export TERM=dumb",
            # Disable command editing features that produce control sequences
            "set +o vi +o emacs",
            # Disable the "bracketed paste mode" (generates [?2004h/l)
            # And disable line editing
            'echo -e "\\033[?2004l"',
            # Disable color and special prompts in common shells
            "export PS1='\\$ '",  # Set a simple prompt
            "export PS2='> '",  # Set a simple secondary prompt
            "alias ls='ls --color=never'",  # Disable colors in ls
            # Disable various command completions and suggestions
            "bind 'set disable-completion on'",  # For bash
        ]

        # Send each setup command
        for cmd in terminal_setup_commands:
            try:
                self.channel.send(cmd + "\n")
                time.sleep(0.1)
                # Clear output from setup commands
                while self.channel.recv_ready():
                    self.channel.recv(4096)
            except Exception:
                # Skip if a command fails, it might not be supported in the user's shell
                pass

        # Final short wait to ensure settings are applied
        time.sleep(0.5)
        # Clear any remaining output
        while self.channel.recv_ready():
            self.channel.recv(4096)

    def _check_success(self) -> bool:
        marker = f"EXITCODE_MARKER_{int(time.time())}"
        exit_cmd = f"echo '{marker}'$?'{marker}'"

        self.channel.send(f"{exit_cmd}\n")
        exit_code_output = self._read_until_prompt(log=False)
        pattern = re.escape(marker) + r"\s*(\d+)\s*" + re.escape(marker)
        exit_code_match = re.search(pattern, exit_code_output, re.DOTALL)

        return int(exit_code_match.group(1)) == 0

    def execute_commands(
        self, commands: str, timeout: int = None, print_result: bool = True
    ):
        results = []
        success = True

        for cmd in commands:
            success, output = self.execute_command(cmd.strip(), timeout)
            # output.replace('\r\n', '\n')
            if print_result:
                prompt = "✅ Command succeeded:" if success else "❌ Command failed:"
                print(f"{prompt} {cmd}")
                results.append({"command": cmd, "output": output, "success": success})
                if not success:
                    print(f"Output:\n{output}")
                    if self.exit_on_fail:
                        break
        return results

    def execute_command(
        self, command: str, timeout: int = 30, check_exit_code: bool = True
    ) -> Tuple[bool, str]:
        """
        Execute a single command and return the result

        Args:
            command: Command to execute
            timeout: Maximum time to wait for completion in seconds
            check_exit_code: Whether to check the command exit code

        Returns:
            Tuple[bool, str]: Success status and command output
        """
        if not self.connected:
            return False, "Not connected to server"
        output = ""
        try:
            # Send command with newline
            self._write_log(command + "\n")
            self.channel.send(command + "\n")

            # Get command output
            output = self._read_until_prompt(timeout=timeout)

            if check_exit_code:
                success = self._check_success()
                if not success:
                    self._write_log(
                        f"{output}\n\nCommand failed with exit code: {success}"
                    )
                    return False, output

            return True, output

        except Exception as e:
            self._write_log(f"Error executing command: {str(e)}")
            return False, str(e)

    def execute_script(
        self,
        script_path: str,
        remote: bool = False,
        args: List[str] = None,
        timeout: int = 120,
    ) -> Tuple[bool, str]:
        """
        Execute a script on the remote server

        Args:
            script_path: Path to the script (local or remote)
            remote: Whether the path is on remote server
            args: Script arguments
            timeout: Maximum execution time in seconds

        Returns:
            Tuple[bool, str]: Success status and output
        """
        if not self.connected:
            return False, "Not connected to server"

        if args is None:
            args = []

        try:
            if not remote:
                # Upload local script to remote server
                with open(script_path, "r") as f:
                    script_content = f.read()

                remote_path = f"/tmp/{os.path.basename(script_path)}"
                upload_cmd = (
                    f"cat > {remote_path} << 'EOFSCRIPT'\n{script_content}\nEOFSCRIPT\n"
                )

                self.channel.send(upload_cmd)
                self._read_until_prompt()

                # Make executable
                self.channel.send(f"chmod +x {remote_path}\n")
                self._read_until_prompt()

                script_path = remote_path

            # Execute script with arguments
            args_str = " ".join(args)
            cmd = f"{script_path} {args_str}"

            self._write_log(f"Executing script: {cmd}")
            self.channel.send(cmd + "\n")

            output = self._read_until_prompt(timeout=timeout)

            # Check exit code
            exit_code = self._check_success()

            if not exit_code:
                self._write_log(f"{output} Script failed with exit code: {exit_code}")
                return False, output

            self._write_log(f"{output} Script executed successfully")
            return True, output

        except Exception as e:
            self._write_log(f"Error executing script: {str(e)}")
            return False, str(e)

    def _write_log(self, message):
        """Write to log file with timestamp"""
        # timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        # self.log.write(f"[{timestamp}] {message}\n")
        self.log.write(f"{message}")
        self.log.flush()

    def _read_until_prompt(self, timeout: int = 30, log=True) -> str:
        """
        Read from channel until a shell prompt is found or timeout occurs

        Args:
            timeout: Maximum time to wait in seconds
            prompt_pattern: Regular expression to match the shell prompt

        Returns:
            str: Command output excluding the prompt
        """
        prompt_pattern = (
            r"[$#>]( |)$" if self.prompt is None else re.escape(self.prompt)
        )
        output = ""
        start_time = time.time()

        while timeout is None or (time.time() - start_time) < timeout:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode("ascii", errors="replace")
                output += chunk
                if log:
                    self._write_log(chunk)

                # Check if we've reached a shell prompt
                if re.search(prompt_pattern, output):
                    break
            else:
                time.sleep(0.1)

        if timeout is not None and (time.time() - start_time) >= timeout:
            self._write_log("Timeout waiting for command completion")

        return output

    def _wait_for_device(self, max_wait=600):
        """Wait for the device to be reachable."""
        start_time = time.time()

        print(f"Waiting for device {self.host} to come online...")

        # Wait for ping to succeed
        while True:
            try:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", self.host],
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
        print(f"device {self.host} is online...")
        return True

    def _detect_prompt_pattern(self, output: str) -> None:
        """
        Automatically detect the prompt pattern from output

        Args:
            output: Initial output from the shell
        """
        for pattern in self._common_prompt_patterns:
            match = re.search(pattern, output)
            if match:
                self._detected_prompt_pattern = pattern
                print(f"Detected prompt pattern: {pattern}")
                return

        # If no pattern is detected, we'll use a default pattern
        self._detected_prompt_pattern = r"[\r\n](>|\$|#)\s*$"
        print("Using default prompt pattern as no specific pattern was detected")


# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        "host": "pek-lpggp9",
        #'telnet_server': '128.224.164.38',
        "username": "jchan-cn",
        "password": "3jchan-cn",
        # 'key_filename': '/path/to/key.pem',
        "log_dir": "/buildarea/jchan/bisect/efficient-tools/bisect-script",
    }
    commands = ["uname -a", "invalid_command"]

    # Create and use SSH client
    ssh = SSHClient(**config)

    if ssh.connect():
        try:
            # Example: Execute single command
            output = ssh.execute_commands(commands)

            # Example: Execute heredoc with multiple commands
            heredoc_commands = [
                "echo 'Starting multi-command script'",
                "cd /tmp",
                "mkdir -p test_dir",
                "cd test_dir",
                "echo 'Hello, world!' > test.txt",
                "cat test.txt",
                "echo 'Script completed'",
            ]
            success, output = ssh.execute_script(
                "/buildarea/jchan/bisect/efficient-tools/bisect-script/bisect-script.sh"
            )
            # success, output = ssh.execute_heredoc(heredoc_commands)
            print(f"Heredoc success: {success}")

        finally:
            # Always close when done
            ssh.close()
