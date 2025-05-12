import os
import re
import subprocess
import telnetlib
import time


class TelnetClient:
    def __init__(
        self,
        host,
        telnet_server,
        username,
        password,
        port=23,
        prompt="# ",
        timeout=5,
        log_dir="",
        exit_on_fail=True,
    ):
        self.host = host
        self.telnet_server = telnet_server
        self.port = port
        self.username = username
        self.password = password
        self.prompt = prompt
        self.timeout = timeout
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, f"telnet-{telnet_server}-{port}.log")
        self.conn = None
        self.log = open(self.log_file, "a")  # Append mode to preserve history
        self.commands = ["dmesg -n 1"]
        self.exit_on_fail = exit_on_fail

        self.namespace = {"client": self}
        self.namespace.update(globals())

    def connect(self):
        """Establish telnet connection and login if credentials are provided"""
        if not self._wait_for_device():
            print(f"device boot up failed")
            return False
        try:
            self.conn = telnetlib.Telnet(self.telnet_server, self.port, self.timeout)

            # Handle login if credentials are provided
            if self.username and self.password:
                self._write("\n")
                self.conn.read_until("login: ".encode("ascii"))
                self._write(self.username)
                self.conn.read_until("Password: ".encode("ascii"), timeout=self.timeout)
                self._write(self.password)

            # Verify successful connection by waiting for prompt
            if self._read_until(self.prompt) == "":
                print("cannot read prompt, connect failed\n")
                return False
            # self.execute_commands(self.commands)
            return True
        except Exception as e:
            print(str(e))
            self._log_error(f"Connection failed: {str(e)}")
            return False

    def execute_commands(self, commands, check_success=True):
        """Execute multiple commands and return results with success status"""
        results = []
        self._read_all_available()
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

    def execute_heredoc(self, command_block, sub_prompt="> ", print_result=True):
        """Execute multi-line commands with prompt handling"""
        self._read_all_available()
        results = []
        output = ""

        commands = command_block.strip().split("\n")
        for cmd in commands:
            output += self.execute_command(cmd.strip(), sub_prompt)
        output.replace("\r\n", "\n")
        results.append({"command": command_block, "output": output, "success": True})

        if print_result:
            print(f"\n{'='*50}")
            for result in results:
                print(f"Command: {result['command']}")
                print(f"Success: {result['success']}")
                # print(f"Output:\n{result['output']}\n{'='*50}")
        return results

    def execute_command(self, command, prompt=None, check_success=True):
        """Execute a single command and return its output"""
        prompt = self.prompt if prompt is None else prompt
        output = ""
        success = True

        if "internal-command:pyfunc:" in command:
            try:
                success, output = eval(command.split(":")[2].strip(), self.namespace)
            except Exception as e:
                success = False
                output = str(e)
            return success, output
        else:
            if "skip-check:" in command:
                command = command.split(":")[1].strip()
                check_success = False

            try:
                self._write(command)
                output = self._read_until(prompt)
            except Exception as e:
                self._log_error(f"Command execution failed: {str(e)}")
                return False, output

        if check_success:
            success = self._check_success(output)
        output.replace("\r\n", "\n")

        return success, output

    def close(self):
        """Close telnet connection and log file"""
        self._write("exit\n")
        if self.conn:
            self.conn.close()
        self.log.close()

    def flush_buffer(self):
        """Read and log any remaining data in the connection"""
        residual_data = self._read_all_available()
        return residual_data

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

    def _write(self, text):
        """Helper method to write to connection"""
        # print(f"{time.time()} send: {text}")
        self.conn.write(text.encode("ascii") + b"\n")

    def _read_all_available(self, timeout=5):
        """Read all remaining data until no more data arrives"""
        buffer = bytearray()
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                chunk = self.conn.read_very_eager()
                if chunk:
                    buffer += chunk
                    start_time = time.time()  # Reset timer if we got data
                    self._write_log(f"{chunk.decode('ascii', errors='ignore')}")
            except EOFError:
                break

        return buffer.decode("ascii", errors="ignore").strip()

    def _read_until(self, expected):
        """Helper method to read until expected string is found"""
        response = self.conn.read_until(expected.encode("ascii"), self.timeout)
        decoded = response.decode("ascii")
        if decoded != "":
            self._write_log(f"{decoded}")
        return decoded

    def _check_success(self, output):
        """Check if command execution was successful (customize as needed)"""
        exit_code = False
        marker = f"EXITCODE_MARKER_{int(time.time())}"
        exit_cmd = f"echo '{marker}'$?'{marker}'"

        self._read_all_available()
        self._write(exit_cmd)
        response = self.conn.read_until(
            self.prompt.encode("ascii"), self.timeout
        ).decode("ascii")

        pattern = re.escape(marker) + r"\s*(\d+)\s*" + re.escape(marker)
        exit_code_match = re.search(pattern, response, re.DOTALL)

        if exit_code_match:
            exit_code = int(exit_code_match.group(1)) == 0

        if exit_code:
            error_keywords = ["error", "invalid", "denied", "failed"]
            exit_code = not any(keyword in output.lower() for keyword in error_keywords)
        return exit_code

    def _write_log(self, message):
        """Write to log file with timestamp"""
        # timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        # self.log.write(f"[{timestamp}] {message}\n")
        self.log.write(f"{message}")
        self.log.flush()  # Ensure immediate writing

    def _log_error(self, message):
        """Handle error logging"""
        self._write_log(f"ERROR: {message}")


# Example usage
if __name__ == "__main__":
    # Configuration - replace with your server details
    config = {
        "host": "128.224.179.132",
        "telnet_server": "128.224.164.38",
        "port": 2008,
        "username": "root",
        "password": "root",
        "prompt": "# ",
        "log_dir": "/buildarea/jchan/bisect/efficient-tools/bisect-script",
    }

    commands = ["uname -a", "invalid_command"]

    shell_script = """
    cat <<EOF > /tmp/config.cfg
    [server]
    port = 8080
    telnet_server = 0.0.0.0
    EOF
    chmod 600 /tmp/config.cfg
    cat /tmp/config.cfg
    """

    # Create client and execute commands
    client = TelnetClient(**config)

    if client.connect():
        results = client.execute_commands(commands)
        output = client.execute_heredoc(shell_script)

        client.close()
    else:
        print("Failed to connect to server")
