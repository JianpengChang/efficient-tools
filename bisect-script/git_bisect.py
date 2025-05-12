#!/usr/bin/env python3
# what to do next:
# 1. add bisect log after failure, skip the checked commit when re-run
# 2.
from contextlib import nullcontext
import os
import sys
import subprocess
import shutil
import time
import logging
from typing import Tuple
from telnetExecutor import TelnetClient
from sshExecutor import SSHClient
from configManager import YAMLConfigManager


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
            return False, "create process failed"

        if "skip-check:" in command:
            command = command.split(":")[1].strip()
            force_true = True

        if self.is_echo:
            self.log.write(f"{self.prompt}{command}\n")

        if command == "":
            return True, ""

        if "internal-command:pyfunc:" in command:
            try:
                return_code, output = eval(
                    command.split(":")[2].strip(), self.namespace
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


def handle_counter():
    if os.path.exists(COUNTER_FILE):
        with open(COUNTER_FILE, "r") as f:
            counter = int(f.read()) + 1
    else:
        counter = 1

    if counter == 1:
        if os.path.exists(LOG_BASE_DIR):
            shutil.rmtree(LOG_BASE_DIR)

    with open(COUNTER_FILE, "w") as f:
        f.write(str(counter))

    return counter


def get_commit_hash():
    """get current commit hash ID"""
    os.chdir(global_vars["KERNEL_SRC_DIR"])
    result = subprocess.run(
        "git rev-parse --short HEAD", shell=True, capture_output=True, text=True
    )
    os.chdir(SCRIPT_DIR)
    return result.stdout.strip()


def main():
    # init counter
    counter = handle_counter()

    # create log directory
    commit_hash = get_commit_hash()
    commit_log_dir = os.path.join(LOG_BASE_DIR, f"{counter}-{commit_hash}")
    local_log = os.path.join(commit_log_dir, "local.log")

    if os.path.exists(commit_log_dir):
        shutil.rmtree(commit_log_dir)
    os.makedirs(commit_log_dir, exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        handlers=[logging.FileHandler(local_log), logging.StreamHandler()],
    )

    # Create a logger
    global logger
    logger = logging.getLogger(__name__)

    # f = open(local_log, "w")
    logger.info(f"=== start check commit: {commit_hash} ===\n")
    logger.info(time.strftime("%Y-%m-%d %H:%M:%S") + "\n")

    execute_items = loaded_config.get_expanded_items()
    exit_code = 0
    for item in execute_items:
        # 2 seconds to wait hardware to start work
        time.sleep(2)
        logger.info(item["desc"] + "\n")
        if item["env"] is None:
            item["env"] = {}
        item["env"]["log_dir"] = commit_log_dir
        if item["client"] == "telnet":
            client = TelnetClient(**item["env"])
        elif item["client"] == "ssh":
            client = SSHClient(**item["env"])
        elif item["client"] == "localhost":
            client = LocalhostClient(**item["env"])

        if "funcs" in item:
            for i in item["funcs"]:
                if i["type"] == "pyfunc":
                    exec(i["source"], client.namespace)

        output = []
        if client.connect():
            try:
                output = client.execute_commands(item["commands"].strip().split("\n"))
            except Exception as e:
                print(str(e))
            client.close()
        else:
            sys.exit(1)

        print("=" * 50)
        for result in output:
            if not result["success"]:
                logger.error(f"{result['command']} failed\nOutput: {result['output']}")
                exit_code = 1

        if exit_code != 0:
            sys.exit(exit_code)


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

LOG_BASE_DIR = os.path.join(SCRIPT_DIR, "bisect_logs")
COUNTER_FILE = os.path.join(SCRIPT_DIR, "bisect_counter")
SSH_OPTIONS = "-o ConnectTimeout=10 -o LogLevel=INFO -o StrictHostKeyChecking=no"
loaded_config = YAMLConfigManager()
loaded_config.load_from_yaml("env.yaml")
global_vars = loaded_config.expand_globals()

# main()
if __name__ == "__main__":
    main()
