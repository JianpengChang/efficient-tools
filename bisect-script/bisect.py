#!/usr/bin/env python3
# what to do next:
# 1. add bisect log after failure, skip the checked commit when re-run
# 2. use logger to make the log more readable
import os
import sys
import subprocess
import shutil
import time


def load_env_config():
    with open(os.path.join(SCRIPT_DIR, "env.cfg"), "r") as file:
        env_configurations = file.read()

    return env_configurations


def echo_commands(commands, hostname=None):
    prefix = "run "
    ECHO_COMMAND = f"""run() {{ echo "jchan-cn@{hostname}$ $@"; "$@";}}
"""
    lines = commands.splitlines()

    prefixed_lines = [prefix + line for line in lines]

    return ECHO_COMMAND + "\n".join(prefixed_lines)


def run_command(cmd, log_file=None, cwd=None, is_echo=True):
    """execute shell commands and write output to log and terminal in time"""
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
                print(output.strip())
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


def get_device_ip():
    cmd = f"/folk/vlm/commandline/vlmTool getAttr -t {BOARD_ID} all"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    board_ip = None

    for line in result.stdout.split("\n"):
        if "IP Address" in line:
            board_ip = line.split(":")[1].strip()
    if board_ip is None:
        print(f"cannot get IP for board {BOARD_ID}", file=sys.stderr)
    return board_ip


def get_commit_hash():
    """get current commit hash ID"""
    os.chdir(KERNEL_SRC_DIR)
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

    f = open(local_log, "w")
    f.write(f"=== start check commit: {commit_hash} ===\n")
    f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "\n")

    f.write("=== start compile linux kernel ===\n")
    exit_code = run_command(COMPILE_COMMAND, local_log, cwd=KERNEL_SRC_DIR)
    if exit_code != 0:
        sys.exit(exit_code)

    f.write("NFS server deployment...\n")
    nfs_cmd = [
        REMOTE_EXECUTOR,
        "-u",
        "root",
        "-i",
        "jchang1-Meteor",
        "-k",
        os.path.expanduser("~/.ssh/id_rsa"),
        "-l",
        commit_log_dir,
        "-c",
        NFS_DEPLOY,
    ]
    exit_code = subprocess.call(nfs_cmd)
    if exit_code != 0:
        sys.exit(exit_code)

    f.write("execute reboot...\n")
    exit_code = run_command(REBOOT_COMMAND, local_log, cwd=KERNEL_SRC_DIR)
    if exit_code != 0:
        sys.exit(exit_code)

    time.sleep(REBOOT_WAIT_TIME)

    # execute from remote ssh
    f.write("execute remote test commands...\n")
    device_ip = get_device_ip()
    if device_ip is None:
        sys.exit(1)
    subprocess.call(
        f"ssh-keygen -f \"{os.path.expanduser('~/.ssh/known_hosts')}\" -R \"{device_ip}\"",
        shell=True,
    )

    remote_cmd = [
        REMOTE_EXECUTOR,
        "-u",
        "root",
        "-i",
        device_ip,
        "-p",
        "root",
        "-l",
        commit_log_dir,
        "-c",
        TEST_COMMAND,
        "-o",
        SSH_OPTIONS,
    ]
    exit_code = subprocess.call(remote_cmd)
    sys.exit(exit_code)


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
exec(load_env_config())

REMOTE_EXECUTOR = os.path.join(SCRIPT_DIR, "remote_executor.sh")
LOG_BASE_DIR = os.path.join(SCRIPT_DIR, "bisect_logs")
COUNTER_FILE = os.path.join(SCRIPT_DIR, "bisect_counter")
SSH_OPTIONS = "-o ConnectTimeout=10 -o LogLevel=INFO -o StrictHostKeyChecking=no"
test_print = False
if test_print:
    print(COMPILE_COMMAND)
    print(NFS_DEPLOY)
    print(REBOOT_COMMAND)
    print(TEST_COMMAND)
    print(handle_counter())
    print(get_device_ip())
    print(get_commit_hash())
main()
