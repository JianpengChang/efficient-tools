#!/usr/bin/env python3
# what to do next:
# 1. add bisect log after failure, skip the checked commit when re-run
# 2.
import argparse
import os
import sys
import subprocess
import shutil
import time
import logging
from typing import Tuple
from executorClient import SSHClient, LocalhostClient, TelnetClient
from configManager import YAMLConfigManager


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


def main(execute_items):
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

    exit_code = 0
    for item in execute_items:
        # wait hardware to start work
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

# main()
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Configurations for bisect.')
    parser.add_argument('--conf', type=str, required=True, help='configuration file for bisect')
    args = parser.parse_args()

    loaded_config = YAMLConfigManager()
    loaded_config.load_from_yaml(args.conf)
    global global_vars
    global_vars = loaded_config.expand_globals()
    execute_items = loaded_config.get_expanded_items()

    main(execute_items)
