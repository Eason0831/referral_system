# Gunicorn配置文件

# 绑定地址和端口
bind = "0.0.0.0:8000"

# 工作进程数
workers = 4

# 工作模式
worker_class = "sync"

# 超时设置
timeout = 120

# 每个工作进程的线程数
threads = 2

# 工作进程预加载应用
preload_app = True

# 守护进程模式运行
daemon = False

# 应用模块路径
pythonpath = "."
application = "app:app"

# 日志设置
accesslog = "logs/access.log"
errorlog = "logs/error.log"
loglevel = "info"

# 确保日志目录存在
import os
if not os.path.exists("logs"):
    os.makedirs("logs") 