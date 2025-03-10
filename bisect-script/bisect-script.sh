#!/bin/bash -x

# 退出码说明：
# 0 - 正常（good commit）
# 1 - 异常（bad commit）
# 125 - 跳过此commit（如编译失败）

# 定义关键路径和参数
SCRIPT_DIR=$(dirname "$(realpath "$0")")
REMOTE_EXECUTOR="$SCRIPT_DIR/remote_executor.sh"

source $SCRIPT_DIR/env.cfg

SSH_OPTIONS="-o ConnectTimeout=10 -o LogLevel=INFO -o StrictHostKeyChecking=no"
DEVICE_IP=$(/folk/vlm/commandline/vlmTool getAttr -t $BOARD_ID all | grep "IP Address" | cut -d ":" -f 2)

# yocto project parameters
YOCTO_SRC_CACHE="YOCTO_PROJECT_BASE/layers/wrlinux/wrlinux/recipes-kernel/linux/srcrev.inc"

LOG_BASE_DIR="$SCRIPT_DIR/bisect_logs"

COUNTER_FILE="$SCRIPT_DIR/bisect_counter"
# 初始化或读取计数器
if [ -f "$COUNTER_FILE" ]; then
    COUNTER=$(cat "$COUNTER_FILE")
    COUNTER=$((COUNTER + 1))
else
    COUNTER=1
fi
if [ $COUNTER -eq 1 ]; then
    rm -rf $LOG_BASE_DIR
fi
echo "$COUNTER" > "$COUNTER_FILE"

# 获取当前commit信息
COMMIT_HASH=$(cd $KERNEL_SRC_DIR && git rev-parse --short HEAD)
COMMIT_LOG_DIR="$LOG_BASE_DIR/$COUNTER-$COMMIT_HASH"

# 创建commit专属日志目录
rm -rf "$COMMIT_LOG_DIR" || exit 125
mkdir -p "$COMMIT_LOG_DIR" || exit 125

# 定义日志文件路经
LOCAL_LOG="$COMMIT_LOG_DIR/local.log"

# 编译执行函数
exec_commands() {
    local commands="$1"
    local exit_code=0

    while IFS= read -r cmd; do
        # 跳过空行
        if [ -z "$cmd" ]; then
            continue
        fi
        # echo "Executing: $cmd"
        eval "$cmd"
        exit_code=$?
        if [ $exit_code -ne 0 ]; then
            echo "命令执行失败: $cmd" >&2
            return $exit_code
        fi
    done <<< "$commands"

    return 0
}

# 记录所有本地操作到日志（同时输出到终端）

exec > >(tee -a "$LOCAL_LOG") 2>&1
# 打印commit信息
echo "=== 开始检测 commit: $COMMIT_HASH ==="
date "+%Y-%m-%d %H:%M:%S"

# 清理并编译内核
echo "=== 开始编译内核 ==="
exec_commands "$COMPILE_COMMAND"

if [ $? -ne 0 ] ; then
    exit $?
fi

echo "NFS服务器配置..."
"$REMOTE_EXECUTOR" \
    -u "root" \
    -i "jchang1-Meteor" \
    -k "$HOME/.ssh/id_rsa" \
    -l "$COMMIT_LOG_DIR" \
    -c "$NFS_DEPLOY"

if [ $? -ne 0 ] ; then
    exit $?
fi

echo "$REBOOT_COMMAND"
exec_commands "$REBOOT_COMMAND"
sleep $REBOOT_WAIT_TIME

echo "执行远程命令..."
ssh-keygen -f "\"$HOME/.ssh/known_hosts\"" -R "\"$DEVICE_IP\""
start_ssh_time=$(date +%s)
"$REMOTE_EXECUTOR" \
    -u "root" \
    -i "$DEVICE_IP" \
    -p "root" \
    -l "$COMMIT_LOG_DIR" \
    -c "$TEST_COMMAND" \
    -o "$SSH_OPTIONS"

if [ $? -eq 0 ] ; then
    ssh_exit=0
else
    ssh_exit=$?
fi
ssh_duration=$(( $(date +%s) - start_ssh_time ))

echo "SSH退出码: $ssh_exit, 耗时: ${ssh_duration}s"

if [ $ssh_exit -eq 0 ]; then
    exit 0
else
    exit 1
fi
