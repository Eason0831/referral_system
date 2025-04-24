from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import qrcode
from io import BytesIO
import base64
import hashlib
import random
import string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# 确保数据库目录存在
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
if not os.path.exists(db_path):
    os.makedirs(db_path)

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(db_path, "referral.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 数据模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(10), unique=True, nullable=False) # 只存储10位数字
    password_hash = db.Column(db.String(128))
    referral_code = db.Column(db.String(10), unique=True)
    referred_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    referral_level = db.Column(db.Integer, default=0)  # 用户在推荐树中的层级
    referral_path = db.Column(db.Text)  # 存储推荐路径，格式：1,2,3,4 表示推荐链
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 添加关系
    referrer = db.relationship('User', remote_side=[id], backref='referrals')
    
    def get_total_commission(self):
        """获取用户总佣金"""
        from sqlalchemy import func
        total = db.session.query(func.sum(Commission.amount))\
                .filter_by(user_id=self.id).scalar() or 0
        return total

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Define the relationship to the User model
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

class Commission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    transaction_id = db.Column(db.Integer, db.ForeignKey('transaction.id'))
    amount = db.Column(db.Float, nullable=False)
    level = db.Column(db.Integer, nullable=False)  # 推荐层级（1,2,3,...无限）
    commission_rate = db.Column(db.Float, nullable=False)  # 该层级的佣金比率
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CommissionRate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.Integer, nullable=False)  # 推荐层级
    rate = db.Column(db.Float, nullable=False)  # 佣金比率
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @staticmethod
    def get_rate(level):
        rate = CommissionRate.query.filter_by(level=level, is_active=True).first()
        if rate:
            return rate.rate
        return 0.5 ** (level - 1) * 0.01  # 默认佣金比率：每层减半，第一层1%

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    type = db.Column(db.String(50))  # 'dish', 'drink', 'duck'
    value = db.Column(db.Float)
    is_active = db.Column(db.Boolean, default=True)
    expiry_date = db.Column(db.DateTime, nullable=True)  # 添加过期日期字段
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @property
    def is_expired(self):
        """检查优惠券是否已过期"""
        if self.expiry_date is None:
            return False  # 无过期日期视为永不过期
        return datetime.utcnow() > self.expiry_date

class UserCoupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    coupon_id = db.Column(db.Integer, db.ForeignKey('coupon.id'))
    redemption_code = db.Column(db.String(16), unique=True)  # 添加兑换码
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)
    
    # 添加关系以便轻松获取相关优惠券和用户数据
    coupon = db.relationship('Coupon', backref='user_coupons')
    user = db.relationship('User', backref='coupons')
    
    def __init__(self, **kwargs):
        super(UserCoupon, self).__init__(**kwargs)
        
        # 自动生成随机兑换码 (格式: CP-XXXX-XXXX-XXXX)
        if not kwargs.get('redemption_code'):
            chars = string.ascii_uppercase + string.digits
            code_parts = [''.join(random.choices(chars, k=4)) for _ in range(3)]
            self.redemption_code = f"CP-{code_parts[0]}-{code_parts[1]}-{code_parts[2]}"

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Float, nullable=False)
    method_type = db.Column(db.String(20), nullable=False) # alipay, wechat, emt, member

    # Alipay specific
    alipay_account = db.Column(db.String(100), nullable=True)
    alipay_phone = db.Column(db.String(20), nullable=True)

    # WeChat specific
    wechat_id = db.Column(db.String(100), nullable=True)
    wechat_phone = db.Column(db.String(20), nullable=True)

    # EMT specific
    emt_bank_name = db.Column(db.String(100), nullable=True)
    emt_email = db.Column(db.String(100), nullable=True)
    emt_recipient_name = db.Column(db.String(100), nullable=True)
    emt_phone = db.Column(db.String(20), nullable=True)
    
    # Member account specific
    member_phone = db.Column(db.String(20), nullable=True)
    member_name = db.Column(db.String(100), nullable=True)

    # Common fields
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    submit_token = db.Column(db.String(100)) # Consider removing if CSRF handled differently
    
    # 添加与User的关系
    user = db.relationship('User', backref=db.backref('withdrawals', lazy=True))

class TransactionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 添加数据库初始化代码
def init_db():
    with app.app_context():
        db.create_all()
        # 检查是否已存在管理员账户
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            # 创建默认管理员账户
            admin = User(
                username='quanjude',
                email='admin@example.com',
                phone_number='0000000000', # 为管理员添加一个默认/占位符手机号
                is_admin=True,
                referral_code='ADMIN01',
                referral_level=0, # 确保默认值被设置
                referral_path=''
            )
            # Explicitly specify the hashing method
            admin.password_hash = generate_password_hash('iden1864', method='pbkdf2:sha256')
            db.session.add(admin)
            db.session.commit()
            print("Created default admin account: quanjude/iden1864")
        else:
            # 更新已有管理员账户的用户名和密码
            admin.username = 'quanjude'
            admin.password_hash = generate_password_hash('iden1864', method='pbkdf2:sha256')
            db.session.commit()
            print("Updated admin account to: quanjude/iden1864")
        
        # 初始化佣金比率
        rates = [
            (1, 0.01), # 第一级 1%
            (2, 0.005), # 第二级 0.5%
            (3, 0.0025), # 第三级 0.25%
            (4, 0.00125), # 第四级 0.125%
            (5, 0.000625), # 第五级 0.0625%
        ]
        
        # 检查是否已存在佣金比率
        if not CommissionRate.query.first():
            for level, rate in rates:
                commission_rate = CommissionRate(
                    level=level,
                    rate=rate,
                    is_active=True
                )
                db.session.add(commission_rate)
            db.session.commit()
            print("Initialized commission rates")

# 路由
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/en')
def index_en():
    return render_template('index_en.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        country_code = request.form.get('country_code') # 获取国家代码
        phone_digits = request.form.get('phone_digits') # 获取10位手机号
        referral_code = request.form.get('referral_code')

        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))

        # 检查邮箱是否已存在
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册')
            return redirect(url_for('register'))

        # 验证手机号格式
        if not phone_digits or not phone_digits.isdigit() or len(phone_digits) != 10:
            flash('请输入有效的10位手机号码')
            return redirect(url_for('register'))

        # 检查手机号是否已存在 (只检查10位数字部分)
        if User.query.filter_by(phone_number=phone_digits).first():
            flash('手机号已被注册')
            return redirect(url_for('register'))

        # 获取推荐人信息和构建推荐路径
        referred_by = None
        referral_level = 0
        referral_path = ''

        # 生成唯一的用户推荐码
        user_referral_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        while User.query.filter_by(referral_code=user_referral_code).first():
            user_referral_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

        if referral_code:
            referrer = User.query.filter_by(referral_code=referral_code).first()
            if referrer:
                referred_by = referrer.id
                referral_level = referrer.referral_level + 1
                
                # 构建完整的推荐路径
                if referrer.referral_path:
                    # 如果推荐人有推荐路径，则在路径后面附加推荐人ID
                    referral_path = f"{referrer.referral_path},{referrer.id}"
                else:
                    # 如果推荐人没有推荐路径，则路径为推荐人ID
                    referral_path = str(referrer.id)
                
                app.logger.info(f"用户 {username} 通过推荐码 {referral_code} 注册，" +
                              f"推荐人ID: {referred_by}, 层级: {referral_level}, " +
                              f"推荐路径: {referral_path}")
            else:
                app.logger.warning(f"注册时使用了无效的推荐码: {referral_code}")
                flash('无效的推荐码')
                return redirect(url_for('register'))

        # 创建新用户
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(
            username=username,
            password_hash=password_hash,
            email=email,
            phone_number=phone_digits, # 保存10位手机号
            referral_code=user_referral_code,
            referred_by=referred_by,
            referral_level=referral_level,
            referral_path=referral_path
        )

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('dashboard'))

    # 预设一些国家代码供模板使用
    country_codes = [
        {'code': '+1', 'name': '+1 (北美)'},
        {'code': '+86', 'name': '+86 (中国大陆)'},
        {'code': '+852', 'name': '+852 (中国香港)'},
        {'code': '+886', 'name': '+886 (中国台湾)'},
        {'code': '+44', 'name': '+44 (英国)'},
        # 可以根据需要添加更多
    ]
    return render_template('register.html', country_codes=country_codes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # 使用 Werkzeug 的 check_password_hash 来验证密码
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard') if not user.is_admin else url_for('admin'))
        else:
            flash('用户名或密码错误')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # 获取所有层级的推荐用户 - 改进版使用referral_path进行查询
    def get_all_referrals_data(user_id):
        referrals_data = {}
        current_user_obj = User.query.get(user_id)
        
        # 检查用户是否存在
        if not current_user_obj:
            app.logger.error(f"尝试获取不存在的用户ID={user_id}的推荐数据")
            return {}
        
        app.logger.info(f"获取用户{user_id}的所有推荐层级数据")
        
        # 方法1: 直接查询referred_by字段 - 获取直接推荐的用户（第一级）
        direct_referrals = User.query.filter_by(referred_by=user_id).all()
        if direct_referrals:
            referrals_data[1] = []
            for user in direct_referrals:
                # 计算该用户的总消费金额
                total_spent = db.session.query(db.func.sum(Transaction.amount))\
                    .filter_by(user_id=user.id).scalar() or 0
                    
                # 计算该用户为当前用户贡献的总佣金
                contributed_commission = db.session.query(db.func.sum(Commission.amount))\
                    .filter_by(user_id=current_user.id, level=1)\
                    .join(Transaction, Commission.transaction_id == Transaction.id)\
                    .filter(Transaction.user_id == user.id).scalar() or 0
                    
                referrals_data[1].append({
                    'user': user,
                    'total_spent': total_spent,
                    'contributed_commission': contributed_commission
                })
        
        # 方法2: 使用推荐路径查询间接推荐的用户
        # 获取直接推荐用户的ID列表，用于排除
        direct_referral_ids = [user.id for user in direct_referrals] if direct_referrals else []
        
        max_level = 10  # 最大查询的层级
        for level in range(2, max_level + 1):
            users_at_level = []
            
            # 查询所有在referral_path中包含当前用户ID且层级正确的用户
            for user in User.query.filter(User.referral_level >= level).all():
                if not user.referral_path:
                    continue
                    
                # 解析推荐路径
                path_parts = user.referral_path.split(',')
                
                # 对于第2级用户，当前用户是其直接推荐人的推荐人
                # 对于第3级用户，当前用户是其直接推荐人的推荐人的推荐人，以此类推
                if len(path_parts) >= level:
                    position = -level  # 从路径末尾往前数第level个位置
                    if abs(position) <= len(path_parts) and path_parts[position] == str(user_id):
                        # 确保这个用户不是已经在更低层级计算过的用户
                        if level == 2 and user.id in direct_referral_ids:
                            continue
                        
                        # 计算总消费金额
                        total_spent = db.session.query(db.func.sum(Transaction.amount))\
                            .filter_by(user_id=user.id).scalar() or 0
                            
                        # 计算贡献佣金
                        contributed_commission = db.session.query(db.func.sum(Commission.amount))\
                            .filter_by(user_id=current_user.id, level=level)\
                            .join(Transaction, Commission.transaction_id == Transaction.id)\
                            .filter(Transaction.user_id == user.id).scalar() or 0
                            
                        users_at_level.append({
                            'user': user,
                            'total_spent': total_spent,
                            'contributed_commission': contributed_commission
                        })
            
            if users_at_level:
                referrals_data[level] = users_at_level
        
        # 按层级排序
        return dict(sorted(referrals_data.items()))

    # 获取处理后的推荐用户数据
    all_referrals_processed = get_all_referrals_data(current_user.id)

    # 获取各层级佣金统计 (为当前用户)
    commissions_by_level = {}
    all_user_commissions = Commission.query.filter_by(user_id=current_user.id).all()
    for comm in all_user_commissions:
        commissions_by_level[comm.level] = commissions_by_level.get(comm.level, 0) + comm.amount

    # 计算总佣金
    total_commission = sum(commissions_by_level.values())

    # 计算可用余额 (总佣金 - 已批准或待处理的提现)
    pending_or_approved_withdrawals = db.session.query(db.func.sum(Withdrawal.amount))\
        .filter(
            Withdrawal.user_id == current_user.id,
            Withdrawal.status.in_(['pending', 'approved'])
        ).scalar() or 0
    available_balance = total_commission - pending_or_approved_withdrawals

    # 获取用户的提现记录
    withdrawals = Withdrawal.query.filter_by(user_id=current_user.id).order_by(Withdrawal.created_at.desc()).all()

    # 获取用户的交易记录（充值记录）
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).all()

    # 获取佣金比率配置
    commission_rates = CommissionRate.query.filter_by(is_active=True).order_by(CommissionRate.level).all()
    
    # 获取用户的优惠券
    user_coupons = db.session.query(UserCoupon)\
        .join(Coupon, UserCoupon.coupon_id == Coupon.id)\
        .filter(UserCoupon.user_id == current_user.id)\
        .order_by(UserCoupon.created_at.desc())\
        .all()

    return render_template('dashboard.html',
                         all_referrals_data=all_referrals_processed,
                         commissions_by_level=commissions_by_level,
                         total_commission=total_commission,
                         available_balance=available_balance,
                         withdrawals=withdrawals,
                         transactions=transactions,
                         commission_rates=commission_rates,
                         user_coupons=user_coupons)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    transactions = Transaction.query.order_by(Transaction.created_at.desc()).all()
    coupons = Coupon.query.all()
    
    # 获取优惠券使用情况
    coupon_usage = {}
    total_issued_coupons = UserCoupon.query.count()
    total_used_coupons = UserCoupon.query.filter_by(is_used=True).count()
    
    # 为每种优惠券类型创建统计
    coupon_types = {}
    
    for coupon in coupons:
        user_coupons_for_coupon = UserCoupon.query.filter_by(coupon_id=coupon.id).all()
        used_count = sum(1 for uc in user_coupons_for_coupon if uc.is_used)
        expired_count = sum(1 for uc in user_coupons_for_coupon if not uc.is_used and coupon.is_expired)
        valid_count = len(user_coupons_for_coupon) - used_count - expired_count
        
        coupon_usage[coupon.id] = {
            'total_issued': len(user_coupons_for_coupon),
            'used_count': used_count,
            'expired_count': expired_count,
            'valid_count': valid_count
        }
        
        # 按类型统计
        if coupon.type not in coupon_types:
            coupon_types[coupon.type] = {
                'total': 0, 'used': 0, 'expired': 0, 'valid': 0
            }
        
        coupon_types[coupon.type]['total'] += len(user_coupons_for_coupon)
        coupon_types[coupon.type]['used'] += used_count
        coupon_types[coupon.type]['expired'] += expired_count
        coupon_types[coupon.type]['valid'] += valid_count
    
    # 获取用户佣金和可用余额
    user_commissions = {}
    for user in users:
        total_commission = db.session.query(db.func.sum(Commission.amount))\
                          .filter_by(user_id=user.id).scalar() or 0
        
        pending_or_approved_withdrawals = db.session.query(db.func.sum(Withdrawal.amount))\
            .filter(
                Withdrawal.user_id == user.id, 
                Withdrawal.status.in_(['pending', 'approved'])
            ).scalar() or 0
            
        available_balance = total_commission - pending_or_approved_withdrawals
        
        user_commissions[user.id] = {
            'total_commission': total_commission,
            'available_balance': available_balance
        }
    
    # 获取所有已分配给用户的优惠券
    user_coupons = UserCoupon.query.options(
        db.joinedload(UserCoupon.coupon),
        db.joinedload(UserCoupon.user)
    ).all()
    
    # 准备用于 JSON 序列化的优惠券数据
    user_coupons_serializable = []
    for uc in user_coupons:
        user_coupons_serializable.append({
            'id': uc.coupon.id,
            'type': uc.coupon.type,
            'value': uc.coupon.value,
            'description': uc.coupon.description or '', # 确保描述存在
            'status': '已使用' if uc.is_used else ('已过期' if uc.coupon.is_expired else '未使用'),
            'created_time': uc.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': uc.user_id,
            'username': uc.user.username # 如果需要用户名
        })

    # 今日消费统计
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    today_transactions = Transaction.query.filter(Transaction.created_at.between(today_start, today_end)).all()
    today_total = sum(t.amount for t in today_transactions)
    
    # 推荐人数排行榜 - 增强版：考虑多级推荐
    user_referral_counts = {}
    for user in users:
        # 直接推荐的用户数（第一级）
        direct_referrals = User.query.filter_by(referred_by=user.id).count()
        
        # 通过referral_path查询间接推荐的用户数
        indirect_referrals = 0
        if direct_referrals > 0:
            # 查找所有推荐路径中包含当前用户ID的用户，但不是直接推荐的用户
            # 首先获取所有直接推荐用户的ID列表
            direct_referral_ids = [u.id for u in User.query.filter_by(referred_by=user.id).all()]
            
            # 查询所有包含当前用户ID在推荐路径中的用户，但排除直接推荐的用户和用户自己
            # 注意：需要确保路径格式为逗号分隔的ID列表
            path_pattern = f"%,{user.id},%"  # 中间的情况
            path_start = f"{user.id},%"      # 开始的情况
            path_end = f"%,{user.id}"        # 结束的情况
            path_exact = f"{user.id}"        # 精确匹配（单独一个ID）
            
            indirect_query = User.query.filter(
                (User.referral_path.like(path_pattern)) | 
                (User.referral_path.like(path_start)) | 
                (User.referral_path.like(path_end)) |
                (User.referral_path == path_exact)
            ).filter(User.id != user.id)
            
            # 排除直接推荐的用户，避免重复计算
            if direct_referral_ids:
                indirect_query = indirect_query.filter(~User.id.in_(direct_referral_ids))
            
            indirect_referrals = indirect_query.count()
        
        # 计算用户贡献的总佣金
        total_commission = db.session.query(db.func.sum(Commission.amount))\
                          .filter_by(user_id=user.id).scalar() or 0
        
        user_referral_counts[user.id] = {
            'username': user.username,
            'direct_count': direct_referrals,
            'indirect_count': indirect_referrals,
            'total_count': direct_referrals + indirect_referrals,
            'total_commission': total_commission
        }
    
    # 按总推荐人数排序
    top_referrers = sorted(
        [{'user_id': k, 'username': v['username'], 
          'direct_count': v['direct_count'], 
          'indirect_count': v['indirect_count'],
          'total_count': v['total_count'],
          'total_commission': v['total_commission']}
         for k, v in user_referral_counts.items() if v['total_count'] > 0],
        key=lambda x: x['total_count'],
        reverse=True
    )[:10]  # 只取前10名
    
    # 添加到模板上下文
    template_context = {
        'users': users, 
        'transactions': transactions, 
        'coupons': coupons, 
        'coupon_usage': coupon_usage,
        'coupon_types': coupon_types,
        'total_issued_coupons': total_issued_coupons,
        'total_used_coupons': total_used_coupons,
        'user_commissions': user_commissions, 
        'user_coupons': user_coupons,
        'today_total': today_total, 
        'top_referrers': top_referrers,
        'user_coupons_serializable': user_coupons_serializable # 添加到上下文
    }
    
    return render_template('admin.html', **template_context)

@app.route('/admin/coupon/add', methods=['POST'])
@login_required
def add_coupon():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    type = request.form.get('type')
    value = float(request.form.get('value', 0))
    user_id = request.form.get('user_id')  # 获取选择的用户ID，为空则不分配
    expiry_date_str = request.form.get('expiry_date')  # 获取过期日期字符串
    
    # 转换过期日期字符串为datetime对象
    expiry_date = None
    if expiry_date_str:
        try:
            expiry_date = datetime.fromisoformat(expiry_date_str)
        except ValueError:
            return jsonify({'error': '无效的日期格式'}), 400
    
    try:
        # 创建优惠券
        coupon = Coupon(
            name=name, 
            description=description, 
            type=type, 
            value=value,
            expiry_date=expiry_date
        )
        db.session.add(coupon)
        db.session.flush()  # 获取ID但不提交
        
        message = '优惠券添加成功'
        
        # 如果选择了用户，则直接分配给该用户
        if user_id and user_id.strip():
            try:
                user_id = int(user_id)
                user = User.query.get(user_id)
                if user:
                    user_coupon = UserCoupon(user_id=user_id, coupon_id=coupon.id)
                    db.session.add(user_coupon)
                    message = f'优惠券成功添加并分配给用户 {user.username}，兑换码：{user_coupon.redemption_code}'
                else:
                    message = '优惠券已添加，但找不到所选用户，未能分配'
            except (ValueError, TypeError):
                message = '优惠券已添加，但用户ID无效，未能分配'
        
        db.session.commit()
        return jsonify({'success': True, 'message': message})
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"添加优惠券失败: {str(e)}")
        return jsonify({'error': f'服务器错误: {str(e)}'}), 500

@app.route('/admin/coupon/verify', methods=['POST'])
@login_required
def verify_coupon():
    """验证优惠券的兑换码"""
    if not current_user.is_admin:
        return jsonify({'error': '权限不足'}), 403
    
    if not request.is_json:
        return jsonify({'error': '请求必须是JSON格式'}), 400
    
    data = request.get_json()
    code = data.get('code')
    
    if not code:
        return jsonify({'error': '兑换码不能为空'}), 400
    
    # 查找优惠券
    user_coupon = UserCoupon.query.filter_by(redemption_code=code).first()
    if not user_coupon:
        return jsonify({'error': '无效的兑换码'}), 404
    
    coupon = Coupon.query.get(user_coupon.coupon_id)
    user = User.query.get(user_coupon.user_id)
    
    # 验证优惠券状态
    coupon_valid = True
    status_message = "有效"
    
    if not coupon.is_active:
        coupon_valid = False
        status_message = "此优惠券已被禁用"
    elif coupon.is_expired:
        coupon_valid = False
        status_message = "此优惠券已过期"
    elif user_coupon.is_used:
        coupon_valid = False
        status_message = "此优惠券已被使用"
    
    # 格式化日期和时间以便前端显示
    created_at = user_coupon.created_at.strftime('%Y-%m-%d %H:%M')
    used_at = user_coupon.used_at.strftime('%Y-%m-%d %H:%M') if user_coupon.used_at else None
    
    # 返回验证结果
    return jsonify({
        'success': True,
        'valid': coupon_valid,
        'status_message': status_message,
        'coupon': {
            'id': coupon.id,
            'name': coupon.name,
            'description': coupon.description,
            'type': coupon.type,
            'value': coupon.value,
            'is_active': coupon.is_active,
            'is_expired': coupon.is_expired
        },
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        },
        'user_coupon': {
            'id': user_coupon.id,
            'redemption_code': user_coupon.redemption_code,
            'is_used': user_coupon.is_used,
            'created_at': created_at,
            'used_at': used_at
        }
    })

@app.route('/admin/coupon/redeem', methods=['POST'])
@login_required
def redeem_coupon():
    """将优惠券标记为已使用"""
    if not current_user.is_admin:
        return jsonify({'error': '权限不足'}), 403
    
    if not request.is_json:
        return jsonify({'error': '请求必须是JSON格式'}), 400
    
    data = request.get_json()
    code = data.get('code')
    
    if not code:
        return jsonify({'error': '兑换码不能为空'}), 400
    
    # 查找优惠券
    user_coupon = UserCoupon.query.filter_by(redemption_code=code).first()
    if not user_coupon:
        return jsonify({'error': '无效的兑换码'}), 404
    
    coupon = Coupon.query.get(user_coupon.coupon_id)
    
    # 验证优惠券是否可用
    if not coupon.is_active:
        return jsonify({'error': '此优惠券已被禁用'}), 400
    
    if coupon.is_expired:
        return jsonify({'error': '此优惠券已过期'}), 400
    
    if user_coupon.is_used:
        return jsonify({'error': '此优惠券已被使用'}), 400
    
    try:
        # 标记为已使用
        user_coupon.is_used = True
        user_coupon.used_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '优惠券已成功标记为已使用'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"标记优惠券使用状态失败: {str(e)}")
        return jsonify({'error': f'操作失败: {str(e)}'}), 500

@app.route('/admin/coupon/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_coupon_status(id):
    """切换优惠券的启用/禁用状态"""
    if not current_user.is_admin:
        return jsonify({'error': '权限不足'}), 403
    
    coupon = Coupon.query.get_or_404(id)
    
    try:
        coupon.is_active = not coupon.is_active
        db.session.commit()
        status = "启用" if coupon.is_active else "禁用"
        return jsonify({
            'success': True,
            'message': f'优惠券已{status}'
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"切换优惠券状态失败: {str(e)}")
        return jsonify({'error': f'操作失败: {str(e)}'}), 500

@app.route('/transaction/add', methods=['POST'])
@login_required
def add_transaction():
    if not current_user.is_admin:
        return jsonify({'error': '权限不足，只有管理员可以添加充值记录'}), 403

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
            
        try:
            amount = float(data.get('amount'))
            user_id = int(data.get('user_id'))
        except (ValueError, TypeError):
            return jsonify({'error': '无效的金额或用户ID格式'}), 400
            
        if amount <= 0:
            return jsonify({'error': '充值金额必须大于0'}), 400
            
        # 验证用户是否存在
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
        
        # 创建交易记录
        transaction = Transaction(user_id=user_id, amount=amount)
        db.session.add(transaction)
        db.session.commit()
        
        # 处理佣金 - 支持无限层级的推荐
        def process_commission(user_id, transaction_id, amount, level=1, max_level=10):
            """
            递归处理多级佣金分配
            :param user_id: 获得佣金的用户ID
            :param transaction_id: 交易ID
            :param amount: 交易金额
            :param level: 当前处理的推荐层级
            :param max_level: 最大处理层级，防止过深递归
            """
            if not user_id or level > max_level:
                return
                
            # 获取对应层级的佣金比率
            rate = CommissionRate.get_rate(level)
            if rate <= 0:
                app.logger.info(f"第{level}层佣金比率为0，停止处理")
                return
                
            commission_amount = amount * rate
            app.logger.info(f"为用户{user_id}添加第{level}层佣金：￥{commission_amount:.2f} (费率: {rate:.2%})")
            
            try:
                # 创建佣金记录
                commission = Commission(
                    user_id=user_id,
                    transaction_id=transaction_id,
                    amount=commission_amount,
                    level=level,
                    commission_rate=rate
                )
                db.session.add(commission)
                db.session.flush()  # 立即获取commission.id但不提交事务
                
                # 记录佣金发放日志
                log = TransactionLog(
                    user_id=user_id,
                    type='commission',
                    amount=commission_amount,
                    status='completed',
                    description=f'获得{level}级推荐佣金 ￥{commission_amount:.2f}，费率{rate:.2%}，交易ID: {transaction_id}'
                )
                db.session.add(log)
                
                # 获取上级推荐人
                user = User.query.get(user_id)
                if user and user.referred_by:
                    # 递归处理上级佣金
                    process_commission(user.referred_by, transaction_id, amount, level + 1, max_level)
                else:
                    app.logger.info(f"用户{user_id}没有上级推荐人，佣金链结束")
            except Exception as e:
                app.logger.error(f"处理佣金时出错: {str(e)}")
                raise
        
        # 开始处理佣金分配
        if user.referred_by:
            try:
                process_commission(user.referred_by, transaction.id, amount)
                db.session.commit()
                app.logger.info(f"成功处理用户{user.id}的多级佣金分配")
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"佣金处理失败，已回滚: {str(e)}")
                # 继续处理，不影响主流程
        
        # 给用户发放优惠券（仅当充值金额大于等于1688时）
        coupon_message = ""
        if amount >= 1688:
            try:
                # 创建一张专门的北京烤鸭券
                duck_coupon = Coupon(
                    name='北京烤鸭券',
                    description='充值1688加元以上赠送的北京烤鸭券，价值128加元，仅限堂食使用',
                    type='duck',
                    value=128.00,
                    is_active=True
                )
                db.session.add(duck_coupon)
                db.session.flush()  # 获取ID但不提交
                
                # 分配给用户
                user_coupon = UserCoupon(user_id=user_id, coupon_id=duck_coupon.id)
                db.session.add(user_coupon)
                
                # 记录发放原因
                log = TransactionLog(
                    user_id=user_id,
                    type='coupon_reward',
                    amount=duck_coupon.value,
                    status='completed',
                    description=f'充值奖励：用户充值 CAD$ {amount:.2f}，获得价值 CAD$ {duck_coupon.value:.2f} 的{duck_coupon.name}'
                )
                db.session.add(log)
                db.session.commit()
                
                # 在返回消息中添加优惠券信息
                coupon_message = f"，并获得一张 {duck_coupon.name}（价值: CAD$ {duck_coupon.value:.2f}，仅限堂食）"
            except Exception as e:
                app.logger.error(f"赠送烤鸭券失败: {str(e)}")
                # 继续处理，不影响主流程
        
        return jsonify({
            'success': True,
            'message': f'成功为用户 {user.username} 添加充值记录：CAD$ {amount:.2f}{coupon_message}'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"添加充值记录失败: {str(e)}")
        return jsonify({'error': '添加充值记录失败，请重试'}), 500

@app.route('/referral_link')
@login_required
def referral_link():
    if not current_user.referral_code:
        current_user.referral_code = f"REF{current_user.id:06d}"
        db.session.commit()
    
    # 生成二维码
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    referral_url = url_for('register', referral=current_user.referral_code, _external=True)
    qr.add_data(referral_url)
    qr.make(fit=True)
    
    # 转换二维码为base64图片
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('referral.html', 
                         referral_code=current_user.referral_code,
                         referral_url=referral_url,
                         qr_code=img_str)

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    if not request.is_json:
        return jsonify({'error': '请求必须是JSON格式'}), 400

    data = request.get_json()
    amount_str = data.get('amount')
    method_type = data.get('method_type')

    try:
        amount = float(amount_str)
    except (ValueError, TypeError):
        return jsonify({'error': '无效的提现金额'}), 400

    if amount <= 0:
        return jsonify({'error': '提现金额必须大于0'}), 400

    # 重新计算可用余额以确保最新
    total_commission = db.session.query(db.func.sum(Commission.amount))\
                       .filter_by(user_id=current_user.id).scalar() or 0
    pending_or_approved_withdrawals = db.session.query(db.func.sum(Withdrawal.amount))\
        .filter(
            Withdrawal.user_id == current_user.id,
            Withdrawal.status.in_(['pending', 'approved'])
        ).scalar() or 0
    available_balance = total_commission - pending_or_approved_withdrawals

    if amount > available_balance:
        return jsonify({'error': f'提现金额 CAD$ {amount:.2f} 不能超过可用余额 CAD$ {available_balance:.2f}'}), 400

    # Create withdrawal object based on method_type
    withdrawal = Withdrawal(
        user_id=current_user.id,
        amount=amount,
        method_type=method_type,
        alipay_account=data.get('alipay_account'),
        wechat_id=data.get('wechat_id'),
        emt_bank_name=data.get('emt_bank_name'),
        emt_email=data.get('emt_email'),
        emt_recipient_name=data.get('emt_recipient_name'),
        alipay_phone=data.get('alipay_phone'),
        wechat_phone=data.get('wechat_phone'),
        emt_phone=data.get('emt_phone'),
        member_phone=data.get('member_phone') if method_type == 'member' else None,
        member_name=data.get('member_name') if method_type == 'member' else None,
        status='pending'
    )

    try:
        db.session.add(withdrawal)
        db.session.commit()
        return jsonify({'success': True, 'message': '提现申请已成功提交'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"创建提现记录失败: {str(e)}")
        return jsonify({'error': '服务器内部错误，提现申请失败'}), 500

@app.route('/admin/withdrawals')
@login_required
def admin_withdrawals():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # 使用joined load以避免N+1查询问题
    withdrawals = Withdrawal.query.options(db.joinedload(Withdrawal.user)).order_by(Withdrawal.created_at.desc()).all()
    return render_template('admin_withdrawals.html', withdrawals=withdrawals)

@app.route('/admin/withdrawal/<int:id>/process', methods=['POST'])
@login_required
def process_withdrawal(id):
    if not current_user.is_admin:
        return jsonify({'error': '未授权访问'}), 403
    
    action = request.form.get('action')
    if action not in ['approve', 'reject']:
        return jsonify({'error': '无效的操作'}), 400
    
    withdrawal = Withdrawal.query.get_or_404(id)
    
    # 检查是否已经处理过
    if withdrawal.status != 'pending':
        return jsonify({'error': '该提现申请已经处理过'}), 400
        
    try:
        withdrawal.status = 'approved' if action == 'approve' else 'rejected'
        withdrawal.processed_at = datetime.utcnow()
        # Store the admin who processed it (optional but good practice)
        # You might need to add a 'processed_by' column to the Withdrawal model if you want this
        # withdrawal.processed_by = current_user.id

        if action == 'approve':
            # 记录提现操作日志
            log = TransactionLog(
                user_id=withdrawal.user_id,
                type='withdrawal',
                amount=withdrawal.amount,
                status='completed',
                description=f'提现申请已通过 - 金额: CAD$ {withdrawal.amount}'
            )
            db.session.add(log)
        else:
            # 如果拒绝，金额会自动保留在可用余额中，无需手动添加
            # user = User.query.get(withdrawal.user_id) # No need to fetch user
            # user.available_commission += withdrawal.amount # Incorrect logic, remove this line

            # 记录拒绝日志
            log = TransactionLog(
                user_id=withdrawal.user_id,
                type='withdrawal_rejected',
                amount=withdrawal.amount,
                status='completed',
                description=f'提现申请被拒绝 - 金额: CAD$ {withdrawal.amount} 已保留在余额中' # Updated description
            )
            db.session.add(log)
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': '提现申请已' + ('通过' if action == 'approve' else '拒绝')
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"处理提现申请失败: {str(e)}")
        return jsonify({'error': '处理提现申请时发生错误'}), 500

@app.route('/profile')
@login_required
def profile():
    return redirect(url_for('dashboard'))  # 将profile页面重定向到dashboard

@app.route('/apply_withdraw', methods=['POST'])
@login_required
def apply_withdraw():
    try:
        # 获取并验证表单数据
        data = request.get_json()
        
        # 验证金额
        amount = float(data.get('amount', 0))
        if amount <= 0:
            return jsonify({'success': False, 'message': '提现金额必须大于0'})
        
        # 检查提现金额是否超过用户可用余额
        # 计算可用余额 (总佣金 - 已批准或待处理的提现)
        total_commission = db.session.query(db.func.sum(Commission.amount))\
                       .filter_by(user_id=current_user.id).scalar() or 0
        pending_or_approved_withdrawals = db.session.query(db.func.sum(Withdrawal.amount))\
            .filter(
                Withdrawal.user_id == current_user.id,
                Withdrawal.status.in_(['pending', 'approved'])
            ).scalar() or 0
        available_balance = total_commission - pending_or_approved_withdrawals
        
        if amount > available_balance:
            return jsonify({'success': False, 'message': f'提现金额不能超过可用余额 CAD$ {available_balance:.2f}'})
        
        # 获取提现方式
        method_type = data.get('method_type')
        if not method_type:
            return jsonify({'success': False, 'message': '请选择提现方式'})
        
        # 创建提现记录
        withdrawal = Withdrawal(
            user_id=current_user.id,
            amount=amount,
            method_type=method_type
        )
        
        # 根据不同提现方式设置相关字段
        if method_type == 'alipay':
            withdrawal.alipay_account = data.get('account', '')
            withdrawal.alipay_phone = data.get('phone', '')
            
        elif method_type == 'wechat':
            withdrawal.wechat_id = data.get('account', '')
            withdrawal.wechat_phone = data.get('phone', '')
            
        elif method_type == 'emt':
            withdrawal.emt_bank_name = data.get('bank_name', '')
            withdrawal.emt_email = data.get('account', '')
            withdrawal.emt_recipient_name = data.get('account_name', '')
            withdrawal.emt_phone = data.get('phone', '')
            
        elif method_type == 'member':
            # 新增会员账户提现方式
            withdrawal.member_phone = data.get('member_phone', '')
            withdrawal.member_name = data.get('member_name', '')
            
            # 验证会员账户信息
            if not withdrawal.member_phone or not withdrawal.member_name:
                return jsonify({'success': False, 'message': '请填写会员手机号和姓名'})
        
        # 保存记录到数据库
        db.session.add(withdrawal)
        
        # 创建交易记录
        log = TransactionLog(
            user_id=current_user.id,
            type='withdrawal_request',
            amount=amount,
            status='pending',
            description=f'申请提现 CAD$ {amount:.2f}'
        )
        db.session.add(log)
        
        db.session.commit()
        return jsonify({'success': True, 'message': '提现申请已提交'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"提现申请失败: {str(e)}")
        return jsonify({'success': False, 'message': '提现申请失败，请稍后再试'})

@app.route('/admin/coupon/<int:id>/delete', methods=['POST'])
@login_required
def delete_coupon(id):
    if not current_user.is_admin:
        return jsonify({'error': '未授权访问'}), 403
    
    coupon = Coupon.query.get_or_404(id)
    
    # 检查是否有用户已使用此优惠券
    used_coupons = UserCoupon.query.filter_by(coupon_id=id, is_used=True).first()
    if used_coupons:
        return jsonify({'error': '无法删除已被使用的优惠券'}), 400
    
    try:
        # 删除所有关联的用户优惠券
        UserCoupon.query.filter_by(coupon_id=id).delete()
        
        # 删除优惠券本身
        db.session.delete(coupon)
        db.session.commit()
        
        return jsonify({'success': True, 'message': '优惠券已成功删除'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"删除优惠券时出错: {str(e)}")
        return jsonify({'error': '删除优惠券时发生错误'}), 500

@app.route('/admin/coupon/<int:id>/update-expiry', methods=['POST'])
@login_required
def update_coupon_expiry(id):
    if not current_user.is_admin:
        return jsonify({'error': '未授权访问'}), 403
    
    data = request.get_json()
    expiry_date_str = data.get('expiry_date')
    
    coupon = Coupon.query.get_or_404(id)
    
    try:
        if expiry_date_str and expiry_date_str.strip():
            # 将日期字符串转换为datetime对象
            expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%d')
            coupon.expiry_date = expiry_date
        else:
            # 如果没有提供日期，则设置为None（永不过期）
            coupon.expiry_date = None
        
        db.session.commit()
        return jsonify({'success': True, 'message': '过期日期已更新'})
    except ValueError:
        return jsonify({'error': '无效的日期格式'}), 400
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"更新优惠券过期日期时出错: {str(e)}")
        return jsonify({'error': '更新过期日期时发生错误'}), 500

if __name__ == '__main__':
    init_db()  # 初始化数据库
    app.run(debug=True) 