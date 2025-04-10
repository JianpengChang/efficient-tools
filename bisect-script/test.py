import os
import sys
import subprocess
import shutil
import time
import logging
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

REMOTE_EXECUTOR = os.path.join(SCRIPT_DIR, "executor.py")
TEST_SSH_COMMAND = r"""
    PS1="\u@\H:# "
    uname -a
    cat /proc/cmdline
    dmesg -t | grep "crashkernel reserved"
    cp -f /boot/bzImage /second_kernel
    systemctl restart kdump.service
    systemctl --no-pager status kdump.service
    cat /sys/kernel/kexec_crash_loaded
    """

remote_cmd = [
    "python3",
    REMOTE_EXECUTOR,
    "-u",
    "root",
    "-i",
    "128.224.179.132",
    "-p",
    "root",
    "-l",
    "./logs",
    "-c",
    TEST_SSH_COMMAND,
]
exit_code = subprocess.call(remote_cmd)

TEST_COMMAND = r"""
    PS1="\u@\H:# "
    uname -a
    cat /proc/cmdline
    dmesg -t | grep "crashkernel reserved"
    cp -f /boot/bzImage /second_kernel
    systemctl restart kdump.service
    systemctl --no-pager status kdump.service
    cat /sys/kernel/kexec_crash_loaded
    echo c > /proc/sysrq-trigger
    """
remote_cmd = [
    "python3",
    REMOTE_EXECUTOR,
    "-u",
    "root",
    "-i",
    "128.224.164.38",
    "-p",
    "root",
    "-l",
    "./logs",
    "--port",
    "2008",
    "-m",
    "telnet",
    "-c",
    TEST_COMMAND,
]
exit_code = subprocess.call(remote_cmd)