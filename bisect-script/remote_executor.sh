#!/bin/bash -x
# 用途：可靠的远程命令执行工具
# 输入参数：
#   -u <user>         : SSH用户名（必须）
#   -i <ip>           : 设备IP（必须）
#   -c "<command>"    : 要执行的命令（必须）
#   -l <log_dir>      : 日志存储目录（必须）
#   -k <key_file>     : SSH私钥路径（可选，默认用密码）
#   -p <password>     : SSH密码（可选，与密钥二选一）
#   -o "<ssh_options>": 追加SSH客户端参数（可选）

# 解析命令行参数
while getopts "u:i:c:l:k:p:o:" opt; do
    case $opt in
        u) SSH_USER="$OPTARG" ;;
        i) DEVICE_IP="$OPTARG" ;;
        c) COMMAND="$OPTARG" ;;
        l) LOG_DIR="$OPTARG" ;;
        k) SSH_KEY="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        o) SSH_OPTIONS="$OPTARG" ;;
        *) exit 1 ;;
    esac
done

# 检查必要参数
if [[ -z $SSH_USER || -z $DEVICE_IP || -z $COMMAND || -z $LOG_DIR ]]; then
    echo "缺少必要参数！"
    exit 125
fi

# 创建日志目录
mkdir -p "$LOG_DIR" || exit 125
SSH_LOG="$LOG_DIR/ssh-$DEVICE_IP.log"

# 构建SSH认证参数
if [[ -n $SSH_KEY ]]; then
    AUTH_OPTIONS="-i $SSH_KEY -o IdentitiesOnly=yes"
elif [[ -n $PASSWORD ]]; then
    if ! command -v sshpass &> /dev/null; then
        echo "需要sshpass但未安装!"
        exit 125
    fi
    AUTH_OPTIONS="-o PasswordAuthentication=yes"
    SSH_PREFIX="sshpass -p $PASSWORD"
else
    echo "必须提供密钥或密码!"
    exit 125
fi

# 等待设备可达
wait_for_device() {
    local max_wait=300
    local start_time=$(date +%s)
    
    echo "等待设备 $DEVICE_IP 上线..." 
    while ! ping -c 1 -W 1 $DEVICE_IP &>/dev/null; do
        if [ $(($(date +%s) - start_time)) -ge $max_wait ]; then
            echo "超时：设备未响应"
            exit 125
        fi
        sleep 5
    done
    
    start_time=$(date +%s)
    until nc -z -w 1 $DEVICE_IP 22 &>/dev/null; do
    if [ $(($(date +%s) - start_time)) -ge $max_wait ]; then
        echo "超时：SSH未就绪"
        exit 125
    fi
    sleep 5
    done
}

# 执行远程命令（带重试）
execute_remote() {
    local attempt=0
    local max_attempts=1
    echo "execute command $COMMAND"
    
    while [ $attempt -lt $max_attempts ]; do
        echo "尝试执行命令（第 $((attempt+1)) 次）..."
        
        # 完整命令执行
        $SSH_PREFIX ssh $AUTH_OPTIONS $SSH_OPTIONS $SSH_USER@$DEVICE_IP \
            /bin/bash -s <<EOF > "$SSH_LOG" 2>&1 
            set -eo pipefail
            set -x
            ${COMMAND}
EOF
        
        local exit_code=$?
        
        if [ $exit_code -eq 0 ]; then
            echo "执行成功"
            return 0
        else
            echo "执行失败，退出码: $exit_code"
            sleep $((attempt * 10))
            ((attempt++))
        fi
    done
    
    return $exit_code
}

wait_for_device
execute_remote
exit $?
