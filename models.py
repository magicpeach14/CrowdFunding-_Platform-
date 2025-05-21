from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'donor' or 'donee'
    wallet_balance = db.Column(db.Float, default=0.0)  # New wallet balance field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<User {self.username}>"

class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    collected_amount = db.Column(db.Float, default=0.0)
    donee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    image_file = db.Column(db.String(100), nullable=True, default='default.jpg')

    donee = db.relationship("User", backref="campaigns")

    def __repr__(self):
        return f"<Campaign {self.title}>"

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaign.id'), nullable=True)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    block_hash = db.Column(db.String(256), nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_transactions")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_transactions")
    campaign = db.relationship("Campaign", backref="transactions")
    
    def __repr__(self):
        return f"<Transaction {self.id}>"

# Rename the original Block model to represent the donation blockchain.
class DonationBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.Column(db.Text)  # JSON string of donation transactions
    previous_hash = db.Column(db.String(256), nullable=False)
    hash = db.Column(db.String(256), nullable=False)
    nonce = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f"<DonationBlock {self.index}>"

# New model for the wallet blockchain.
class WalletBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.Column(db.Text)  # JSON string of wallet top-up transactions
    previous_hash = db.Column(db.String(256), nullable=False)
    hash = db.Column(db.String(256), nullable=False)
    nonce = db.Column(db.Integer, default=0)
    
    def __repr__(self):
        return f"<WalletBlock {self.index}>"
