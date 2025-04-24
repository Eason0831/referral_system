#!/bin/bash

# 激活虚拟环境
if [ -d "../venv" ]; then
    source ../venv/bin/activate
fi

# 确保数据库目录存在
mkdir -p database

# 启动方式
if [ "$1" = "dev" ]; then
    # 开发模式
    python app.py
elif [ "$1" = "gunicorn" ]; then
    # Gunicorn模式
    exec gunicorn -b 0.0.0.0:8000 -w 4 'app:app'
else
    # 默认模式
    python app.py
fi 