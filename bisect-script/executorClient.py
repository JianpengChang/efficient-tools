import os
import paramiko
import re
import subprocess
import telnetlib
import time
from typing import List, Tuple, Any
from abc import ABC, abstractmethod

class executorClient(ABC):
    """Base class for all clients, providing common functionality."""

    def __init__(
        self,
        host,
        port,
        username=None,
        password=None,
        prompt="# ",
        timeout=5,
        log_dir="",
        exit_on_fail=True,
        ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.prompt = prompt
        self.timeout = timeout
        self.log_dir = log_dir
        self.exit_on_fail = exit_on_fail

        self.log_file = os.path.join(self.log_dir, f"{self.__class__.__name__.replace('Client', '')}-{self.host}-{self.port}.log")
        self.log = open(self.log_file, "w")

        self.marker = "EXITCODE_MARKER_"

        self.channel = None
        self.namespace = {"client": self}
        self.namespace.update(globals())

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

    def execute_command(self, command, prompt=None, check_success=True):
        """Execute a single command and return its output"""
        prompt = self.prompt if prompt is None else prompt
        output = ""
        success = True
        skip_result = False

        if command == "":
            return True, ""

        if "internal-pyfunc:" in command:
            try:
                success, output = eval(command.split(":")[-1].strip(), self.namespace)
            except Exception as e:
                success = False
                output = str(e)
            return success, output
        else:
            if "skip-check:" in command:
                command = command.split(":")[1].strip()
                check_success = False
                skip_result = True

            try:
                self._write(command)
                if not skip_result:
                    output = self._read_until_prompt(prompt)
            except Exception as e:
                self._log_error(f"Command execution failed: {str(e)}")
                return False, output

        if check_success:
            success = self._check_success()
        output.replace("\r\n", "\n")

        return success, output

    def execute_commands(self, commands, check_success=True, print_result=True):
        """Execute multiple commands and return results with success status"""
        results = []
        success = True

        for cmd in commands:
            success, output = self.execute_command(cmd, check_success=check_success)
            prompt = "✅ Command succeeded:" if success else "❌ Command failed:"
            print(f"{prompt} {cmd}")
            results.append({"command": cmd, "output": output, "success": success})
            if not success:
                print(f"Output:\n{output}")
                if self.exit_on_fail:
                    break
        return results

    def _write_log(self, message):
        """Write to log file with timestamp"""
        # timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        # self.log.write(f"[{timestamp}] {message}\n")
        self.log.write(f"{message}")
        self.log.flush()  # Ensure immediate writing

    def _log_error(self, message):
        """Handle error logging"""
        self._write_log(f"ERROR: {message}")

    @abstractmethod
    def _read_until_prompt(self, expected, timeout, log):
        """Helper method to read until expected string is found"""
        pass

    def _check_success(self):
        """Check if command execution was successful (customize as needed)"""
        exit_code = False
        marker = f"{self.marker}{int(time.time())}"
        exit_cmd = f"echo '{marker}'$?'{marker}'"

        self._write(exit_cmd)
        response = self._read_until_prompt(log=False)

        pattern = re.escape(marker) + r"\s*(\d+)\s*" + re.escape(marker)
        exit_code_match = re.search(pattern, response, re.DOTALL)

        if exit_code_match:
            exit_code = int(exit_code_match.group(1)) == 0

        return exit_code

    @abstractmethod
    def _write(self, text):
        """Helper method to write to connection"""
        pass

    @abstractmethod
    def connect(self):
        """connect to client"""
        pass

    @abstractmethod
    def close(self):
        """Close the connection."""
        pass

class TelnetClient(executorClient):
    DEFAULT_PORT = 23
    def __init__(
        self,
        **kwargs
    ):
        if 'telnet_server' not in kwargs:
            raise ValueError("Host or telnet_server cannot be empty")

        if 'port' not in kwargs:
            kwargs['port'] = self.DEFAULT_PORT

        self.telnet_server = kwargs['telnet_server']
        del kwargs['telnet_server']

        super().__init__(**kwargs)
        self.commands = ["dmesg -n 1"]

    def login(self):
        # Handle login if credentials are provided
        if self.username and self.password:
            self._write("\n")
            self.channel.read_until("login: ".encode("ascii"))
            self._write(self.username)
            self.channel.read_until("Password: ".encode("ascii"), timeout=self.timeout)
            self._write(self.password)

        # set prompt type, and wait for the output for late init components
        self._write(r'exec 2>&1 && PS1="\u@\H:# "')
        self._read_all_available(2)

        self._write('\n')
        prompt = self._read_until_prompt(timeout=2)
        if self.prompt not in prompt:
            print("cannot read prompt, connect failed\n")
            self._write("exit\n")
            return False
        self.prompt = prompt.split("\n")[-1].strip()
        self._write_log(f"reset prompt to {self.prompt}")
        self._read_all_available(2)
        
        return True

    def connect(self):
        """Establish telnet connection and login if credentials are provided"""
        if not self._wait_for_device():
            print(f"device boot up failed")
            return False
        try:
            self.channel = telnetlib.Telnet(self.telnet_server, self.port, self.timeout)

            # self.execute_commands(self.commands)
            return self.login()
        except Exception as e:
            print(str(e))
            self._log_error(f"Connection failed: {str(e)}")
            return False

    def send_ctrl_c(self):
        self.channel.write(b"\x03\x03\x03\n")

    def execute_commands(self, commands, check_success=True, print_result=True):
        """Execute multiple commands and return results with success status"""

        self._read_all_available(2)
        return super().execute_commands(commands, check_success, print_result)

    def close(self):
        """Close telnet connection and log file"""
        self._write("exit\n")
        if self.channel:
            self.channel.close()
        self.log.close()

    def flush_buffer(self):
        """Read and log any remaining data in the connection"""
        residual_data = self._read_all_available()
        return residual_data

    def _write(self, text):
        """Helper method to write to connection"""
        self.channel.write(text.encode("ascii") + b"\n")

    def _read_all_available(self, timeout=10, log=True):
        """
        Read all remaining data until no more data arrives

        args:
            timeout: the Maximum continuous output
        """
        buffer = bytearray()
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                chunk = self.channel.read_very_eager()
                if chunk:
                    buffer += chunk
                    start_time = time.time()  # Reset timer if we got data
                    if log:
                        self._write_log(f"{chunk.decode('ascii', errors='ignore')}")
            except EOFError:
                break

        return buffer.decode("ascii", errors="ignore").strip()

    def _read_until_prompt(self, expected = None, timeout = None, log = True):
        """Helper method to read until expected string is found"""
        if expected is None:
            expected = self.prompt
        response = self.channel.read_until(expected.encode("ascii"), timeout)
        decoded = response.decode("ascii")
        if decoded != "" and log:
            self._write_log(f"{decoded}")
        return decoded

class SSHClient(executorClient):
    """
    Object-oriented SSH client for connecting to servers and executing commands
    with comprehensive logging and result verification.
    """
    DEFAULT_PORT = 22
    def __init__(
        self,
        **kwargs
    ):
        if 'port' not in kwargs:
            kwargs['port'] = self.DEFAULT_PORT
        self.key_filename = None
        if "key_filename" in kwargs:
            self.key_filename = kwargs["key_filename"]
            del kwargs['key_filename']

        super().__init__(**kwargs)

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

            self._write_log(f"Connecting to {self.host}:{self.port}...\n")

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

            self._write(r'exec 2>&1 && PS1="\u@\H:' + f'{self.prompt} "')
            self.prompt = self._read_until_prompt(timeout=1, log=False).split("\n")[-1].strip()
            self._write_log(f"reset prompt to {self.prompt}")

            self.connected = True
            self._write_log(f"Connection established successfully.\n{self.prompt}")
            return True

        except Exception as e:
            self._write_log(f"\nConnection failed: {str(e)}\n")
            return False

    def _configure_terminal(self) -> None:
        """Configure shell to produce clean output without control sequences"""
        # Wait a moment for shell to initialize
        time.sleep(0.5)

        # Set of commands to configure a clean terminal environment
        terminal_setup_commands = [
            # Disable command echo
            # "stty -echo",
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
                self._write(cmd)
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

    def _read_until_prompt(self, expected = None, timeout: int = None, log=True) -> str:
        """
        Read from channel until a shell prompt is found or timeout occurs

        Args:
            timeout: Maximum time to wait in seconds
            expected: Regular expression to match the shell prompt

        Returns:
            str: Command output excluding the prompt
        """
        prompt_pattern = (
            re.escape(expected) if expected is not None else re.escape(self.prompt)
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
            self._write_log("Timeout waiting for command completion\n")

        return output

    def _write(self, text):
        """Helper method to write to connection"""
        self.channel.send(text + "\n")

    def close(self) -> None:
        """Close the SSH connection"""
        if self.client:
            self._write_log("\nDisconnecting from server...")
            self.client.close()
            self.connected = False
            self._write_log("\nConnection closed.")
        self.log.close()

class LocalhostClient:
    """
    Object-oriented Localhost client for executing commands
    with comprehensive logging and result verification.
    """

    def __init__(
        self,
        exit_on_fail=True,
        log_dir: str = "",
    ):
        self.exit_on_fail = exit_on_fail
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, f"lcoalhost.log")
        self.prompt = f"{os.getlogin()}@{os.uname().nodename}$ "
        self.is_echo = True

        self.log = open(self.log_file, "a")

        self.process = None
        self.namespace = {"client": self}
        self.namespace.update(globals())

    def connect(self):
        self.process = subprocess.Popen(
            ["bash", "--norc", "--noprofile"],  # Disable startup files
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        return True

    def _read_until_prompt(self, MARKER):
        return_code = 0
        output = ""
        while True:
            line = self.process.stdout.readline()
            if not line:
                break  # Shell process died
            if MARKER in line:
                return_code = int(line.split(":")[1].strip())
                break
            output += line
            self.log.write(line)
        self.log.flush()
        return return_code == 0, output

    def execute_command(self, command) -> Tuple[bool, str]:
        """Execute a single command and return the result"""

        MARKER = "COMMAND_FINISHED_MARKER"
        return_code = 0
        force_true = False
        output = ""
        full_cmd = ""

        if self.process is None:
            return False, "have not connect to client"

        if "skip-check:" in command:
            command = command.split(":")[1].strip()
            force_true = True

        if self.is_echo:
            self.log.write(f"{self.prompt}{command}\n")

        if command == "":
            return True, ""

        if "internal-pyfunc:" in command:
            try:
                return_code, output = eval(
                    command.split(":")[-1].strip(), self.namespace
                )
            except Exception as e:
                return_code = False
                output = str(e)
        else:
            full_cmd = f"{command}; echo {MARKER}:$?\n"
            self.process.stdin.write(full_cmd)
            self.process.stdin.flush()

            return_code, output = self._read_until_prompt(MARKER)

        if force_true:
            return_code = True

        return return_code, output

    def execute_commands(self, commands):
        """execute shell commands and write output to log and terminal in time"""
        # logger.info(f"execute commands:\n{commands}")
        results = []
        for command in commands:
            return_code, output = self.execute_command(command)

            results.append(
                {"command": command, "output": output, "success": return_code}
            )
            if not return_code:
                print(f"❌ Command failed: {command}")
                print(f"output:\n{output}")
                if self.exit_on_fail:
                    break
            else:
                print(f"✅ Command succeeded: {command}")

        return results

    def close(self):
        """Close telnet connection and log file"""
        if self.process:
            self.process.kill()  # Terminate the shell session
            self.process.stdin.close()
            self.process.wait()
        self.log.close()
