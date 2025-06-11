from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from cryptography.fernet import Fernet
from flask_wtf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp
from flask_wtf.form import FlaskForm
from dotenv import load_dotenv
import os
import logging

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application. Set it in the environment.")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_manager.db'
app.config['WTF_CSRF_TIME_LIMIT'] = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    fernet_key = db.Column(db.String(256), nullable=False)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service = db.Column(db.String(150), nullable=False)
    service_username = db.Column(db.String(150), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(), Length(min=4, max=150), Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username must contain only letters, numbers, or ./_/-")
    ])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=4, max=128)
    ])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(), Length(min=4, max=150), Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username must contain only letters, numbers, or ./_/-")
    ])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=6, max=128), Regexp(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d).+$', message="Password must contain uppercase, lowercase, and a number")
    ])
    submit = SubmitField('Register')

class EntryForm(FlaskForm):
    service = StringField('Service', validators=[
        InputRequired(), Length(min=1, max=150), Regexp(r'^[a-zA-Z0-9 .@_-]+$', message="Service name contains invalid characters")
    ])
    service_username = StringField('Service Username', validators=[
        InputRequired(), Length(min=1, max=150), Regexp(r'^[a-zA-Z0-9@._-]+$', message="Username contains invalid characters")
    ])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=6, max=128)
    ])
    submit = SubmitField('Add Entry')

class DeleteEntryForm(FlaskForm):
    submit = SubmitField('Delete')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = generate_password_hash(form.password.data.strip())
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            logger.warning(f"Registration attempt with existing username: {username}")
            return redirect(url_for('register'))
        fernet_key = Fernet.generate_key().decode()
        new_user = User(username=username, password=password, fernet_key=fernet_key)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful, please log in')
        logger.info(f"New user registered: {username}")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and check_password_hash(user.password, form.password.data.strip()):
            login_user(user)
            logger.info(f"User logged in: {user.username}")
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
        logger.warning(f"Failed login attempt for username: {form.username.data}")
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logger.info(f"User logged out: {current_user.username}")
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = EntryForm()
    delete_form = DeleteEntryForm()
    if form.validate_on_submit():
        cipher_suite = Fernet(current_user.fernet_key.encode())
        service = form.service.data.strip()
        service_username = form.service_username.data.strip()
        password = form.password.data.strip()
        encrypted = cipher_suite.encrypt(password.encode()).decode()
        new_entry = PasswordEntry(service=service, service_username=service_username,
                                  encrypted_password=encrypted, user_id=current_user.id)
        db.session.add(new_entry)
        db.session.commit()
        flash('Password saved successfully')
        logger.info(f"New password entry added by user: {current_user.username}")
        return redirect(url_for('dashboard'))

    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    cipher_suite = Fernet(current_user.fernet_key.encode())
    for entry in entries:
        entry.decrypted_password = cipher_suite.decrypt(entry.encrypted_password.encode()).decode()
    return render_template('dashboard.html', entries=entries, form=form, delete_form=delete_form)

@app.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash('Unauthorized access.')
        logger.warning(f"Unauthorized edit attempt by user {current_user.username} on entry {entry_id}")
        return redirect(url_for('dashboard'))

    form = EntryForm()
    cipher_suite = Fernet(current_user.fernet_key.encode())
    if form.validate_on_submit():
        entry.service = form.service.data.strip()
        entry.service_username = form.service_username.data.strip()
        entry.encrypted_password = cipher_suite.encrypt(form.password.data.strip().encode()).decode()
        db.session.commit()
        flash('Entry updated successfully.')
        logger.info(f"Entry {entry_id} updated by user: {current_user.username}")
        return redirect(url_for('dashboard'))

    if request.method == 'GET':
        entry.decrypted_password = cipher_suite.decrypt(entry.encrypted_password.encode()).decode()
        form.service.data = entry.service
        form.service_username.data = entry.service_username
        form.password.data = entry.decrypted_password
    return render_template('edit_entry.html', form=form, entry=entry)

@app.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_entry(entry_id):
    form = DeleteEntryForm()
    if form.validate_on_submit():
        entry = PasswordEntry.query.get_or_404(entry_id)
        if entry.user_id != current_user.id:
            flash('Unauthorized access.')
            logger.warning(f"Unauthorized delete attempt by user {current_user.username} on entry {entry_id}")
            return redirect(url_for('dashboard'))
        db.session.delete(entry)
        db.session.commit()
        flash('Entry deleted.')
        logger.info(f"Entry {entry_id} deleted by user: {current_user.username}")
        return redirect(url_for('dashboard'))
    flash('Invalid form submission.')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)