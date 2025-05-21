import os
import json
import hashlib
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from models import db, User, Campaign, Transaction, DonationBlock, WalletBlock
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'add_16_bit_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def calculate_hash(index, timestamp, transactions, previous_hash, nonce):
    value = f"{index}{timestamp}{transactions}{previous_hash}{nonce}"
    return hashlib.sha256(value.encode()).hexdigest()


def create_genesis_donation_block():
    genesis = DonationBlock.query.filter_by(index=0).first()
    if genesis:
        return genesis
    genesis_data = {
        "index": 0,
        "timestamp": datetime.utcnow(),
        "transactions": json.dumps([]),
        "previous_hash": "0",
        "nonce": 0
    }
    genesis_hash = calculate_hash(
        genesis_data['index'],
        genesis_data['timestamp'],
        genesis_data['transactions'],
        genesis_data['previous_hash'],
        genesis_data['nonce']
    )
    genesis = DonationBlock(
        index=0,
        timestamp=genesis_data['timestamp'],
        transactions=genesis_data['transactions'],
        previous_hash="0",
        hash=genesis_hash,
        nonce=0
    )
    db.session.add(genesis)
    db.session.commit()
    return genesis

def add_donation_block(transactions_list):
    last_block = DonationBlock.query.order_by(DonationBlock.index.desc()).first()
    index = last_block.index + 1 if last_block else 1
    timestamp = datetime.utcnow()
    transactions_json = json.dumps(transactions_list)
    previous_hash = last_block.hash if last_block else "0"
    nonce = 0  # Simple nonce (no heavy POW)
    new_hash = calculate_hash(index, timestamp, transactions_json, previous_hash, nonce)
    new_block = DonationBlock(
        index=index,
        timestamp=timestamp,
        transactions=transactions_json,
        previous_hash=previous_hash,
        hash=new_hash,
        nonce=nonce
    )
    db.session.add(new_block)
    db.session.commit()
    return new_block


def create_genesis_wallet_block():
    genesis = WalletBlock.query.filter_by(index=0).first()
    if genesis:
        return genesis
    genesis_data = {
        "index": 0,
        "timestamp": datetime.utcnow(),
        "transactions": json.dumps([]),
        "previous_hash": "0",
        "nonce": 0
    }
    genesis_hash = calculate_hash(
        genesis_data['index'],
        genesis_data['timestamp'],
        genesis_data['transactions'],
        genesis_data['previous_hash'],
        genesis_data['nonce']
    )
    genesis = WalletBlock(
        index=0,
        timestamp=genesis_data['timestamp'],
        transactions=genesis_data['transactions'],
        previous_hash="0",
        hash=genesis_hash,
        nonce=0
    )
    db.session.add(genesis)
    db.session.commit()
    return genesis

def add_wallet_block(topup_data):

    last_block = WalletBlock.query.order_by(WalletBlock.index.desc()).first()
    index = last_block.index + 1 if last_block else 1
    timestamp = datetime.utcnow()
    transactions_json = json.dumps({"wallet_topup": topup_data})
    previous_hash = last_block.hash if last_block else "0"
    nonce = 0
    new_hash = calculate_hash(index, timestamp, transactions_json, previous_hash, nonce)
    while not new_hash.startswith("0000"):
        nonce += 1
        new_hash = calculate_hash(index, timestamp, transactions_json, previous_hash, nonce)
    new_block = WalletBlock(
        index=index,
        timestamp=timestamp,
        transactions=transactions_json,
        previous_hash=previous_hash,
        hash=new_hash,
        nonce=nonce
    )
    db.session.add(new_block)
    db.session.commit()
    return new_block

# ---------------- Routes ------------------

@app.route('/')
def index():
    campaigns = Campaign.query.order_by(Campaign.timestamp.desc()).all()
    latest_donations = Transaction.query.order_by(Transaction.timestamp.desc()).limit(5).all()
    total_target = sum(c.target_amount for c in campaigns)
    total_collected = sum(c.collected_amount for c in campaigns)
    return render_template('index.html', 
                           campaigns=campaigns, 
                           latest_donations=latest_donations, 
                           total_target=total_target, 
                           total_collected=total_collected)

@app.route('/info')
def info():
    campaigns = Campaign.query.order_by(Campaign.timestamp.desc()).all()
    total_target = sum(c.target_amount for c in campaigns)
    total_collected = sum(c.collected_amount for c in campaigns)
    return render_template('info.html', campaigns=campaigns, total_target=total_target, total_collected=total_collected)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'donee':
        campaigns = Campaign.query.filter_by(donee_id=current_user.id).all()
        return render_template('dashboard.html', campaigns=campaigns)
    else:
        user_transactions = Transaction.query.filter(Transaction.sender_id == current_user.id).all()
        return render_template('dashboard.html', transactions=user_transactions)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username         = request.form.get('username')
        email            = request.form.get('email')
        role             = request.form.get('role')  # donor or donee
        password         = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            flash('User already exists!', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role=role, wallet_balance=0.0)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/create_campaign', methods=['GET', 'POST'])
@login_required
def create_campaign():
    if current_user.role != 'donee':
        flash('Only donation receivers (donee) can create campaigns!', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        target_amount = request.form.get('target_amount')
        try:
            target_amount = float(target_amount)
        except ValueError:
            flash('Invalid target amount!', 'danger')
            return redirect(url_for('create_campaign'))
        
        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
        else:
            filename = 'default.jpg'
        
        new_campaign = Campaign(
            title=title,
            description=description,
            target_amount=target_amount,
            donee_id=current_user.id,
            image_file=filename
        )
        db.session.add(new_campaign)
        db.session.commit()
        flash('Campaign created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_campaign.html')

@app.route('/campaigns')
def campaigns():
    campaigns = Campaign.query.order_by(Campaign.timestamp.desc()).all()
    return render_template('campaigns.html', campaigns=campaigns)

@app.route('/campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def campaign_detail(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if request.method == 'POST':
        if current_user.role != 'donor':
            flash('Only donors can make donations!', 'danger')
            return redirect(url_for('campaign_detail', campaign_id=campaign_id))
        try:
            amount = float(request.form.get('amount'))
        except ValueError:
            flash('Invalid donation amount!', 'danger')
            return redirect(url_for('campaign_detail', campaign_id=campaign_id))
        
        # Check wallet balance before donation
        if current_user.wallet_balance < amount:
            flash('Insufficient wallet funds. Please top up your wallet.', 'danger')
            return redirect(url_for('wallet'))
        
        # Deduct amount from donor's wallet
        current_user.wallet_balance -= amount
        db.session.commit()

        transaction = Transaction(
            sender_id=current_user.id,
            receiver_id=campaign.donee_id,
            campaign_id=campaign.id,
            amount=amount,
            block_hash="pending"
        )
        db.session.add(transaction)
        db.session.commit()

        campaign.collected_amount += amount
        db.session.commit()

        tx_data = {
            "transaction_id": transaction.id,
            "donor": current_user.username,
            "donee": campaign.donee.username,
            "campaign": campaign.title,
            "amount": amount,
            "timestamp": transaction.timestamp.isoformat()
        }
        new_block = add_donation_block([tx_data])
        transaction.block_hash = new_block.hash
        db.session.commit()

        flash('Donation successful and recorded on the blockchain!', 'success')
        return redirect(url_for('campaign_detail', campaign_id=campaign_id))
    return render_template('campaign_detail.html', campaign=campaign)

# ---------------- Wallet Routes ------------------

@app.route('/wallet')
@login_required
def wallet():
    return render_template('wallet.html', wallet_balance=current_user.wallet_balance)

@app.route('/topup', methods=['GET', 'POST'])
@login_required
def topup():
    if request.method == 'POST':
        try:
            topup_amount = float(request.form.get('amount'))
        except ValueError:
            flash('Invalid amount!', 'danger')
            return redirect(url_for('topup'))
        if topup_amount <= 0:
            flash('Top-up amount must be greater than zero!', 'danger')
            return redirect(url_for('topup'))
        
        # Prepare top-up data and create a wallet blockchain block
        topup_data = {
            "user_id": current_user.id,
            "username": current_user.username,
            "amount": topup_amount,
            "timestamp": datetime.utcnow().isoformat()
        }
        new_wallet_block = add_wallet_block(topup_data)
        
        # Update user's wallet balance
        current_user.wallet_balance += topup_amount
        db.session.commit()
        
        flash(f'Wallet topped up by {topup_amount}! Wallet Block Hash: {new_wallet_block.hash}', 'success')
        return redirect(url_for('wallet'))
    return render_template('topup.html')

@app.route('/blockchain')
def blockchain():
    donation_blocks = DonationBlock.query.order_by(DonationBlock.index.asc()).all()
    wallet_blocks = WalletBlock.query.order_by(WalletBlock.index.asc()).all()
    
    # Parse transactions for display
    for block in donation_blocks:
        try:
            block.tx_list = json.loads(block.transactions)
        except Exception:
            block.tx_list = []
    for block in wallet_blocks:
        try:
            block.tx_list = json.loads(block.transactions)
        except Exception:
            block.tx_list = []
    return render_template('blockchain.html', donation_blocks=donation_blocks, wallet_blocks=wallet_blocks)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_genesis_donation_block()
        create_genesis_wallet_block()
    app.run(debug=True)
