import os
import logging
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, flash, jsonify
from flask_wtf import FlaskForm, CSRFProtect
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp

import mysql.connector
from dotenv import load_dotenv
import bcrypt

from cryptography.fernet import Fernet

# ============================================
# LOAD ENVIRONMENT VARIABLES
# ============================================

load_dotenv()

# ============================================
# FLASK APPLICATION SETUP
# ============================================

app = Flask(__name__)

# Secret Key Validation
app.secret_key = os.getenv('FLASK_SECRET_KEY')

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from environment variables")

# Session Security
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Enable Session + CSRF
Session(app)
csrf = CSRFProtect(app)

# HTTPS Security Headers
Talisman(
    app,
    force_https=False,
    content_security_policy=None
)

# Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ============================================
# LOGGING CONFIGURATION
# ============================================

logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============================================
# ENCRYPTION SETUP
# ============================================

fernet_key = os.getenv('FERNET_KEY')

if not fernet_key:
    raise RuntimeError("FERNET_KEY is missing from environment variables")

fernet = Fernet(fernet_key.encode())

# ============================================
# DATABASE CONFIGURATION
# ============================================

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': 'passwordsdb'
}

if not db_config['user'] or not db_config['password']:
    raise RuntimeError("Database credentials missing from environment variables")

# ============================================
# FAILED LOGIN TRACKING
# ============================================

failed_login_attempts = {}

# ============================================
# DATABASE INITIALIZATION
# ============================================

def init_db():
    try:
        conn = mysql.connector.connect(
            host=db_config['host'],
            user=db_config['user'],
            password=db_config['password']
        )

        cursor = conn.cursor()

        cursor.execute("CREATE DATABASE IF NOT EXISTS passwordsdb")

        conn.commit()

        cursor.close()
        conn.close()

        conn = mysql.connector.connect(**db_config)

        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                service_name VARCHAR(255) NOT NULL,
                account_username VARCHAR(255) NOT NULL,
                account_password VARCHAR(255) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()

        logging.info("Database initialized successfully")

    except mysql.connector.Error as err:
        logging.error(f"Database initialization error: {err}")
        raise

    finally:
        if 'cursor' in locals():
            cursor.close()

        if 'conn' in locals() and conn.is_connected():
            conn.close()

init_db()

# ============================================
# FORMS
# ============================================

class LoginForm(FlaskForm):

    username = StringField(
        'Username',
        validators=[DataRequired()]
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=12),
            Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])',
                message="Password must include uppercase, lowercase, number, and special character."
            )
        ]
    )

    submit = SubmitField('Login')


class CreateUserForm(FlaskForm):

    username = StringField(
        'Username',
        validators=[
            DataRequired(),
            Length(min=3, max=255)
        ]
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(),
            Length(min=12),
            Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])',
                message="Password must include uppercase, lowercase, number, and special character."
            )
        ]
    )

    confirm_password = PasswordField(
        'Confirm Password',
        validators=[
            DataRequired(),
            EqualTo('password')
        ]
    )

    submit = SubmitField('Create Account')


class ManageAccountsForm(FlaskForm):

    service_name = StringField(
        'Service Name',
        validators=[
            DataRequired(),
            Length(max=255)
        ]
    )

    account_username = StringField(
        'Account Username',
        validators=[DataRequired()]
    )

    account_password = PasswordField(
        'Account Password',
        validators=[
            DataRequired(),
            Length(min=12),
            Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])',
                message="Password must include uppercase, lowercase, number, and special character."
            )
        ]
    )

    submit = SubmitField('Add or Update')


class DeleteAccountForm(FlaskForm):

    service_name = StringField(
        'Service Name',
        validators=[DataRequired()]
    )

    account_username = StringField(
        'Account Username',
        validators=[DataRequired()]
    )

    submit = SubmitField('Delete')

# ============================================
# VALIDATE USER SESSION
# ============================================

def validate_user_id(user_id):

    try:
        conn = mysql.connector.connect(**db_config)

        cursor = conn.cursor()

        cursor.execute(
            'SELECT id FROM users WHERE id = %s',
            (user_id,)
        )

        user = cursor.fetchone()

        return user is not None

    except mysql.connector.Error as err:
        logging.error(f"validate_user_id error: {err}")
        return False

    finally:
        if 'cursor' in locals():
            cursor.close()

        if 'conn' in locals() and conn.is_connected():
            conn.close()

# ============================================
# ROUTES
# ============================================

@app.route('/')
def root():
    return redirect('/login')

# ============================================
# LOGIN ROUTE
# ============================================

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():

    if 'user_id' in session and validate_user_id(session['user_id']):
        return redirect('/manage-accounts')

    session.clear()

    login_form = LoginForm()
    create_user_form = CreateUserForm()

    if request.method == 'POST':

        if login_form.validate_on_submit():

            username = login_form.username.data
            password = login_form.password.data.encode('utf-8')

            # Account Lockout
            if username in failed_login_attempts:

                if failed_login_attempts[username] >= 5:

                    logging.warning(f"Account lockout triggered for user: {username}")

                    flash(
                        'Account temporarily locked due to too many failed attempts.',
                        'error'
                    )

                    return redirect('/login')

            try:
                conn = mysql.connector.connect(**db_config)

                cursor = conn.cursor()

                cursor.execute(
                    'SELECT id, password_hash FROM users WHERE username = %s',
                    (username,)
                )

                user = cursor.fetchone()

                if user and bcrypt.checkpw(
                    password,
                    user[1].encode('utf-8')
                ):

                    session['user_id'] = user[0]
                    session['username'] = username
                    session.permanent = True
                    session['reauthenticated'] = False

                    failed_login_attempts[username] = 0

                    logging.info(f"Successful login: {username}")

                    return redirect('/manage-accounts')

                failed_login_attempts[username] = \
                    failed_login_attempts.get(username, 0) + 1

                logging.warning(f"Failed login attempt: {username}")

                flash('Invalid username or password', 'error')

            except mysql.connector.Error as err:

                logging.error(f"Database error during login: {err}")

                flash('Database error occurred.', 'error')

            finally:
                if 'cursor' in locals():
                    cursor.close()

                if 'conn' in locals() and conn.is_connected():
                    conn.close()

    return render_template(
        'index.html',
        login_form=login_form,
        create_user_form=create_user_form,
        manage_accounts_form=ManageAccountsForm(),
        delete_account_form=DeleteAccountForm(),
        show_login=True
    )

# ============================================
# CREATE USER
# ============================================

@app.route('/create-user', methods=['GET', 'POST'])
def create_user():

    if 'user_id' in session and validate_user_id(session['user_id']):
        return redirect('/manage-accounts')

    session.clear()

    login_form = LoginForm()
    create_user_form = CreateUserForm()

    if request.method == 'POST' and create_user_form.validate_on_submit():

        username = create_user_form.username.data

        password = create_user_form.password.data.encode('utf-8')

        password_hash = bcrypt.hashpw(
            password,
            bcrypt.gensalt()
        ).decode('utf-8')

        try:
            conn = mysql.connector.connect(**db_config)

            cursor = conn.cursor()

            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (%s, %s)',
                (username, password_hash)
            )

            conn.commit()

            logging.info(f"New account created: {username}")

            flash('Account created successfully! Please log in.', 'success')

            return redirect('/login')

        except mysql.connector.Error as err:

            logging.error(f"Create user error: {err}")

            flash(f'Error: {err}', 'error')

        finally:
            if 'cursor' in locals():
                cursor.close()

            if 'conn' in locals() and conn.is_connected():
                conn.close()

    return render_template(
        'index.html',
        login_form=login_form,
        create_user_form=create_user_form,
        manage_accounts_form=ManageAccountsForm(),
        delete_account_form=DeleteAccountForm(),
        show_create=True
    )

# ============================================
# MANAGE ACCOUNTS
# ============================================

@app.route('/manage-accounts', methods=['GET', 'POST'])
def manage_accounts():

    if 'user_id' not in session or not validate_user_id(session['user_id']):

        session.clear()

        return redirect('/login')

    manage_accounts_form = ManageAccountsForm()

    user_id = session['user_id']

    if request.method == 'POST' and manage_accounts_form.validate_on_submit():

        service_name = manage_accounts_form.service_name.data

        account_username = manage_accounts_form.account_username.data

        account_password = manage_accounts_form.account_password.data

        try:
            conn = mysql.connector.connect(**db_config)

            cursor = conn.cursor()

            cursor.execute(
                '''
                SELECT id FROM accounts
                WHERE user_id = %s
                AND service_name = %s
                AND account_username = %s
                ''',
                (user_id, service_name, account_username)
            )

            exists = cursor.fetchone()

            encrypted_password = fernet.encrypt(
                account_password.encode()
            ).decode()

            if exists:

                cursor.execute(
                    '''
                    UPDATE accounts
                    SET account_password = %s
                    WHERE user_id = %s
                    AND service_name = %s
                    AND account_username = %s
                    ''',
                    (
                        encrypted_password,
                        user_id,
                        service_name,
                        account_username
                    )
                )

                logging.info(
                    f"Password updated for {service_name} by {session['username']}"
                )

                flash('Existing account updated successfully!', 'success')
                
            else:

                cursor.execute(
                    '''
                    INSERT INTO accounts
                    (user_id, service_name, account_username, account_password)
                    VALUES (%s, %s, %s, %s)
                    ''',
                    (
                        user_id,
                        service_name,
                        account_username,
                        encrypted_password
                    )
                )

                logging.info(
                    f"New account added for {service_name} by {session['username']}"
                )

                flash('Account added successfully!', 'success')
                
            conn.commit()

            return redirect('/manage-accounts')

        except mysql.connector.Error as err:

            logging.error(f"Manage account error: {err}")

            flash(f'Error: {err}', 'error')

        finally:
            if 'cursor' in locals():
                cursor.close()

            if 'conn' in locals() and conn.is_connected():
                conn.close()

    stored_accounts = []

    try:
        conn = mysql.connector.connect(**db_config)

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT service_name, account_username
            FROM accounts
            WHERE user_id = %s
            ORDER BY service_name, account_username
            ''',
            (user_id,)
        )

        stored_accounts = cursor.fetchall()

    except mysql.connector.Error as err:

        logging.error(f"Fetch account error: {err}")

        flash(f'Error fetching accounts: {err}', 'error')

    finally:
        if 'cursor' in locals():
            cursor.close()

        if 'conn' in locals() and conn.is_connected():
            conn.close()

    return render_template(
        'index.html',
        login_form=LoginForm(),
        create_user_form=CreateUserForm(),
        manage_accounts_form=manage_accounts_form,
        delete_account_form=DeleteAccountForm(),
        stored_accounts=stored_accounts,
        show_manage=True
    )

# ============================================
# DELETE ACCOUNT
# ============================================

@app.route('/delete-account', methods=['POST'])
def delete_account():

    if 'user_id' not in session or not validate_user_id(session['user_id']):

        session.clear()

        return redirect('/login')

    form = DeleteAccountForm()

    if form.validate_on_submit():

        service_name = form.service_name.data

        account_username = form.account_username.data

        user_id = session['user_id']

        try:
            conn = mysql.connector.connect(**db_config)

            cursor = conn.cursor()

            cursor.execute(
                '''
                DELETE FROM accounts
                WHERE user_id = %s
                AND service_name = %s
                AND account_username = %s
                ''',
                (
                    user_id,
                    service_name,
                    account_username
                )
            )

            conn.commit()

            if cursor.rowcount > 0:

                logging.warning(
                    f"Account deleted: {service_name} by {session['username']}"
                )

                flash('Account deleted successfully!', 'success')

            else:
                flash('Account not found!', 'error')

        except mysql.connector.Error as err:

            logging.error(f"Delete account error: {err}")

            flash(f'Error: {err}', 'error')

        finally:
            if 'cursor' in locals():
                cursor.close()

            if 'conn' in locals() and conn.is_connected():
                conn.close()

    return redirect('/manage-accounts')

# ============================================
# SECURE PASSWORD RETRIEVAL
# ============================================

@app.route('/reauthenticate', methods=['POST'])
def reauthenticate():

    print("DEBUG: Reauthenticate route reached")
    
    if 'user_id' not in session:
        return jsonify({'success': False}), 401

    password = request.json.get('password')

    try:

        conn = mysql.connector.connect(**db_config)

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT password_hash
            FROM users
            WHERE id = %s
            ''',
            (session['user_id'],)
        )

        user = cursor.fetchone()

        if user and bcrypt.checkpw(
            password.encode('utf-8'),
            user[0].encode('utf-8')
        ):

            session['reauthenticated'] = True

            return jsonify({
                'success': True
            })

        return jsonify({
            'success': False
        })

    finally:

        if 'cursor' in locals():
            cursor.close()

        if 'conn' in locals() and conn.is_connected():
            conn.close()
            

@app.route('/api/accounts/<service>/<username>', methods=['GET'])
def get_account(service, username):

    if 'user_id' not in session or not validate_user_id(session['user_id']):
        return jsonify({'error': 'Unauthorized'}), 401

    if not session.get('reauthenticated'):
        return jsonify({'error': 'Reauthentication required'}), 403

    user_id = session['user_id']

    try:
        conn = mysql.connector.connect(**db_config)

        cursor = conn.cursor()

        cursor.execute(
            '''
            SELECT account_username, account_password
            FROM accounts
            WHERE user_id = %s
            AND service_name = %s
            AND account_username = %s
            ''',
            (user_id, service, username)
        )

        account = cursor.fetchone()

        if account:

            decrypted_password = fernet.decrypt(
                account[1].encode()
            ).decode()

            return jsonify({
                'service_name': service,
                'account_username': account[0],
                'account_password': decrypted_password
            })

        return jsonify({'error': 'Account not found'}), 404

    except mysql.connector.Error as err:

        logging.error(f"Retrieve password error: {err}")

        return jsonify({'error': 'Database error'}), 500

    finally:
        if 'cursor' in locals():
            cursor.close()

        if 'conn' in locals() and conn.is_connected():
            conn.close()

# ============================================
# LOGOUT
# ============================================

@app.route('/logout', methods=['GET', 'POST'])
def logout():

    username = session.get('username')

    logging.info(f"User logged out: {username}")

    session.clear()

    flash('You have been logged out.', 'success')

    return redirect('/login')

# ============================================
# APPLICATION START
# ============================================

if __name__ == '__main__':

    debug_mode = os.getenv('FLASK_ENV') == 'development'

    app.run(debug=debug_mode)
