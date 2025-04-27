#!/usr/bin/env python3
# what to do next:
# 1. add bisect log after failure, skip the checked commit when re-run
# 2. 
import os
import sys
import subprocess
import shutil
import time
import logging
from telnetExecutor import TelnetClient
from sshExecutor import SSHClient
from configManager import YAMLConfigManager


def echo_commands(commands, hostname=None):
    prefix = "run "
    ECHO_COMMAND = f"""run() {{ echo "jchan-cn@{hostname}$ $@"; "$@";}}
"""
    lines = commands.splitlines()

    prefixed_lines = [prefix + line for line in lines]

    return ECHO_COMMAND + "\n".join(prefixed_lines)


def run_command(cmd, log_file=None, cwd=None, is_echo=True):
    """execute shell commands and write output to log and terminal in time"""
    logger.info(f"execute commands:\n{cmd}")
    if is_echo:
        cmd = echo_commands(cmd, os.uname().nodename)
    with open(log_file, "a") if log_file else nullcontext() as log_handle:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            text=True,
            executable="/bin/bash",
        )
        while True:
            output = process.stdout.readline()
            if output == "" and process.poll() is not None:
                break
            if output:
                # print(output.strip())
                if log_handle:
                    log_handle.write(output)
        if log_handle:
            log_handle.flush()
        return process.poll()


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
        logger.info(item["desc"] + "\n")
        item["env"]["log_dir"] = commit_log_dir
        if item["client"] == "telnet":
            client = TelnetClient(**item["env"])
        elif item["client"] == "ssh":
            client = SSHClient(**item["env"])

        if client.connect():
            output = client.execute_commands(item["commands"].strip().split('\n'))
            for result in output:
                if not result['success']:
                    logger.error(f"{result['command']} failed\nOutput: {result['output']}")
                    exit_code = 1
            client.close()
        else:
            sys.exit(1)

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
