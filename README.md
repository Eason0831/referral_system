# 全聚德推荐系统

一个基于Flask的多层级推荐系统，允许用户通过推荐获得佣金，并支持多种提现方式。

## 系统功能

- 多层级推荐系统（支持无限层级，默认跟踪3层）
- 佣金自动计算与分配
- 优惠券生成与管理
- 用户提现申请与管理
- 管理员后台
- 响应式设计，支持移动设备

## 在Ubuntu上部署

### 系统要求

- Ubuntu 18.04/20.04/22.04
- Python 3.8+
- pip3
- Git

### 安装步骤

1. **更新系统并安装所需软件**

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git
```

2. **克隆代码库**

```bash
git clone https://your-repository-url/全聚德推荐系统.git
cd 全聚德推荐系统
```

3. **创建并激活虚拟环境**

```bash
python3 -m venv venv
source venv/bin/activate
```

4. **安装依赖**

```bash
pip install -r requirements.txt
```

### 配置应用

1. **数据库配置**

默认情况下，应用使用SQLite数据库。数据库文件将自动创建在`database`目录中。

如果要修改数据库配置，请编辑`app.py`文件中的以下部分：

```python
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(db_path, "referral.db")}'
```

2. **密钥配置**

为了安全起见，请修改`app.py`中的密钥：

```python
app.config['SECRET_KEY'] = 'your-new-secure-key-here'
```

为了生成安全的密钥，可以使用Python的`secrets`模块：

```bash
python3 -c "import secrets; print(secrets.token_hex(16))"
```

### 运行应用

1. **初始化数据库并启动应用**

有多种方式启动应用：

```bash
# 方式1：使用start.sh脚本
chmod +x start.sh
./start.sh

# 方式2：直接运行应用
python app.py
```

首次运行时，应用会自动创建数据库和默认管理员账户。

2. **设置为服务（可选）**

创建一个systemd服务文件，以便系统启动时自动运行应用：

```bash
sudo nano /etc/systemd/system/quanjude.service
```

添加以下内容（请根据实际路径进行修改）：

```
[Unit]
Description=全聚德推荐系统
After=network.target

[Service]
User=<your-username>
WorkingDirectory=/path/to/全聚德推荐系统/referral_system
Environment="PATH=/path/to/全聚德推荐系统/venv/bin"
ExecStart=/path/to/全聚德推荐系统/referral_system/start.sh

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl enable quanjude
sudo systemctl start quanjude
```

3. **使用Gunicorn和Nginx进行生产部署（推荐）**

确保Gunicorn已经安装：

```bash
pip install gunicorn
```

配置Nginx：

```bash
sudo apt install -y nginx
```

创建Nginx配置文件：

```bash
sudo nano /etc/nginx/sites-available/quanjude
```

添加以下内容：

```
server {
    listen 80;
    server_name http://52.52.95.171/;  # 替换为您的域名

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # 静态文件处理
    location /static {
        alias /path/to/referral_system/static;
    }
}
```

启用配置并重启Nginx：

```bash
sudo ln -s /etc/nginx/sites-available/quanjude /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 访问系统

- 应用将在 http://localhost:5000 (开发模式) 或您配置的域名上运行
- 默认管理员账户:
  - 用户名: quanjude
  - 密码: iden1864

首次登录后，建议立即修改默认密码。

## 安全注意事项

1. 更改默认管理员密码
2. 使用HTTPS加密连接（使用Let's Encrypt可免费获取SSL证书）
3. 定期备份数据库
4. 为系统添加防火墙规则

```bash
# 只允许HTTP、HTTPS和SSH流量
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

## 常见问题

### 数据库问题

如果遇到数据库错误，可以尝试重新初始化：

```bash
# 进入Python交互式环境
python3
```

```python
from app import db, init_db
db.drop_all()  # 警告：这将删除所有数据
init_db()
exit()
```

### 权限问题

确保应用有权访问其目录和数据库文件：

```bash
sudo chown -R <your-username>:<your-username> /path/to/全聚德推荐系统/referral_system
```

### 日志查看

使用systemd服务时，可以这样查看日志：

```bash
sudo journalctl -u quanjude
```

## 备份

定期备份数据库文件：

```bash
# 手动备份
cp database/referral.db ~/backups/referral_$(date +%Y%m%d).db

# 设置自动备份（crontab）
(crontab -l ; echo "0 2 * * * cp /path/to/全聚德推荐系统/referral_system/database/referral.db /path/to/backups/referral_\$(date +\%Y\%m\%d).db") | crontab -
```

## 联系方式

如需技术支持，请联系：

- 邮箱：support@example.com
- 电话：010-65112418 