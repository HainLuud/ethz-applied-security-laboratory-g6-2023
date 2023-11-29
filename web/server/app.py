#!/usr/bin/env python3

import base64
import io
import os
import re
import urllib.parse
from datetime import timedelta
from functools import wraps

import bcrypt
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import (Flask, abort, flash, g, redirect, render_template,
                   render_template_string, request, send_file, session,
                   url_for)
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

DATABASE_DB = os.getenv('DATABASE_DB')
DATABASE_USER = os.getenv('DATABASE_USER')
DATABASE_PASSWORD_FILE = os.getenv('DATABASE_PASSWORD_FILE')
with open(DATABASE_PASSWORD_FILE, 'r') as f:
    DATABASE_PASSWORD = f.read().strip()
DATABASE_HOST = os.getenv('DATABASE_HOST')
WEB_SECRET_KEY_FILE = os.getenv('WEB_SECRET_KEY_FILE')
with open(WEB_SECRET_KEY_FILE, 'r') as f:
    WEB_SECRET_KEY = f.read().strip()
WEB_CSRF_SECRET_KEY_FILE = os.getenv('WEB_CSRF_SECRET_KEY_FILE')
with open(WEB_CSRF_SECRET_KEY_FILE, 'r') as f:
    WEB_CSRF_SECRET_KEY = f.read().strip()
CA_HOST = os.getenv('CA_HOST')

MAX_UID_LENGTH = 64
MAX_LASTNAME_LENGTH = 64
MAX_FIRSTNAME_LENGTH = 64
MAX_EMAIL_LENGTH = 64
MIN_PWD_LENGTH = 14
MAX_PWD_LENGTH = 72
MAX_PWD_HASH_LENGTH = 64
MIN_PASSPHRASE_LENGTH = 14
MAX_PASSPHRASE_LENGTH = 32

app = Flask(__name__)
Talisman(app)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{DATABASE_DB}'
app.config['SECRET_KEY'] = WEB_SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = WEB_CSRF_SECRET_KEY
db = SQLAlchemy(app, engine_options={
    'connect_args': {
        'auth_plugin': 'caching_sha2_password',
        'ssl_verify_identity': True,
        'ssl_ca': '/run/secrets/ca_root_cert',
    }
})
csrf = CSRFProtect(app)


class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'MyISAM'}

    uid = db.Column(db.String(MAX_UID_LENGTH), primary_key=True)
    lastname = db.Column(db.String(MAX_LASTNAME_LENGTH), nullable=False)
    firstname = db.Column(db.String(MAX_FIRSTNAME_LENGTH), nullable=False)
    email = db.Column(db.String(MAX_EMAIL_LENGTH), nullable=False)
    pwd = db.Column(db.String(MAX_PWD_HASH_LENGTH), nullable=False)

    @property
    def is_admin(self) -> bool:
        return self.uid == 'admin'

    @property
    def name(self) -> str:
        if self.firstname and self.lastname:
            return f'{self.firstname} {self.lastname}'
        if self.firstname:
            return self.firstname
        if self.lastname:
            return self.lastname
        return self.uid

    def update_pwd(self, pwd: str) -> str:
        self.pwd = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())

    def check_pwd(self, pwd: str) -> bool:
        return bcrypt.checkpw(pwd.encode(), self.pwd.encode())


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect(url_for('get_login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            return redirect(url_for('get_login', next=request.path))
        if not g.user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)


@app.before_request
def load_user():
    g.user = db.session.get(User, session['uid']) if 'uid' in session else None


@app.errorhandler(400)
def handle_csrf_error(e):
    return render_template('error.html', code=400, title='Bad Request', message='Your request is missing required information or is malformed.'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, title='Forbidden', message='You do not have permission to access the requested resource.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, title='Page Not Found', message='The page you are looking for could not be found.'), 404


@app.errorhandler(500)
def not_found(e):
    return render_template('error.html', code=500, title='Internal Server Error', message='The server encountered an internal error.'), 500


@app.get('/')
@login_required
def index():
    return render_template('index.html', render_template_string=render_template_string)


@app.get('/crl')
@login_required
def get_crl():
    try:
        response = requests.get(f'https://{CA_HOST}/crl', verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        crl = base64.b64decode(data['crl'].encode())
        return send_file(io.BytesIO(crl), download_name='crl.pem', mimetype='application/x-pem-file')
    except RuntimeError:
        app.logger.exception('')
        abort(500)


@app.get('/login')
def get_login():
    original_next = request.args.get('next')

    next = '/' + request.args.get('next', url_for('index')).lstrip('/')
    next = next if next != url_for('get_logout') else url_for('index')

    if original_next != next:
        return redirect(url_for('get_login', next=next))

    has_cert = 'HTTP_X_SSL_CERT' in request.environ
    return render_template('login.html', next=next, has_cert=has_cert)


@app.post('/login')
def post_login():
    uid = request.form.get('uid')
    pwd = request.form.get('pwd')

    next = '/' + request.form.get('next', url_for('index')).lstrip('/')
    next = next if next != url_for('get_logout') else url_for('index')

    if not uid or not pwd:
        abort(400)

    user = db.session.get(User, uid)

    if not user or user.is_admin or not user.check_pwd(pwd):
        flash('Wrong user ID or password.', 'error')
        return redirect(url_for('get_login', next=next))

    flash('Logged in.', 'info')
    session['uid'] = user.uid
    return redirect(next)


@app.post('/login_cert')
def post_login_cert():
    next = '/' + request.form.get('next', url_for('index')).lstrip('/')
    cert_data = urllib.parse.unquote(request.environ.get('HTTP_X_SSL_CERT'))

    if not cert_data:
        abort(400)

    cert = x509.load_pem_x509_certificate(cert_data.encode())
    try:
        commonname = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except:
        abort(400)

    match = re.search(r'(?P<uid>.*)\.imovies\.ch', commonname)
    if not match:
        abort(400)

    uid = match.group('uid')
    serial_id = cert.serial_number

    try:
        response = requests.get(f'https://{CA_HOST}/user_certificates/{uid}/{serial_id}', verify='/run/secrets/ca_root_cert')
        data = response.json()

        if data['status'] != 'success':
            raise RuntimeError(data['message'])

        certificate = data['certificate']

        if certificate['revoked']:
            flash('The certificate provided was revoked.', 'error')
            return redirect(url_for('get_login', next=next))

        user = db.session.get(User, uid)

        if not user:
            user = User(uid=uid, lastname=certificate['lastname'], firstname=certificate['firstname'], email=certificate['email'], pwd='')
            db.session.add(user)
            db.session.commit()

        flash('Logged in.', 'info')
        session['uid'] = user.uid
        session['cert_data'] = cert_data
        return redirect(next)
    except RuntimeError:
        app.logger.exception('')
        abort(500)


@app.get('/profile/', defaults={'uid': None})
@app.get('/profile/<string:uid>')
@login_required
def get_profile(uid):
    if not uid:
        return redirect(url_for('get_profile', uid=g.user.uid))

    if not g.user.is_admin and g.user.uid != uid:
        abort(403)

    user = db.session.get(User, uid)

    if not user:
        abort(404)

    try:
        response = requests.get(f'https://{CA_HOST}/user_certificates/{user.uid}', verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        certificates = data['certificates']
    except RuntimeError:
        app.logger.exception('')
        certificates = None

    return render_template(
        'profile.html',
        MAX_UID_LENGTH=MAX_UID_LENGTH,
        MAX_LASTNAME_LENGTH=MAX_LASTNAME_LENGTH,
        MAX_FIRSTNAME_LENGTH=MAX_FIRSTNAME_LENGTH,
        MAX_EMAIL_LENGTH=MAX_EMAIL_LENGTH,
        MIN_PWD_LENGTH=MIN_PWD_LENGTH,
        MAX_PWD_LENGTH=MAX_PWD_LENGTH,
        MIN_PASSPHRASE_LENGTH=MIN_PASSPHRASE_LENGTH,
        MAX_PASSPHRASE_LENGTH=MAX_PASSPHRASE_LENGTH,
        user=user,
        certificates=certificates,
    )


@app.post('/profile/<string:uid>/change_password')
@login_required
def post_change_password(uid):
    if (g.user.is_admin and g.user.uid == uid) or (not g.user.is_admin and g.user.uid != uid):
        abort(403)

    user = db.session.get(User, uid)

    if not user:
        abort(404)

    pwd = request.form.get('pwd')

    is_valid_pwd = pwd and MIN_PWD_LENGTH <= len(pwd) <= MAX_PWD_LENGTH

    if not is_valid_pwd:
        abort(400)

    if not g.user.is_admin:
        oldpwd = request.form.get('oldpwd')

        if not oldpwd:
            abort(400)

        if not user.check_pwd(oldpwd):
            flash('Wrong old password.', 'error')
            return redirect(url_for('get_profile', uid=user.uid))

    user.update_pwd(pwd)

    db.session.commit()

    flash('Password changed.', 'info')
    return redirect(url_for('get_profile', uid=user.uid))


@app.post('/profile/<string:uid>/issue')
@login_required
def post_issue(uid):
    if (g.user.is_admin and g.user.uid == uid) or (not g.user.is_admin and g.user.uid != uid):
        abort(403)

    user = db.session.get(User, uid)

    if not user:
        abort(404)

    lastname = request.form.get('lastname')
    firstname = request.form.get('firstname')
    email = request.form.get('email')
    passphrase = request.form.get('passphrase')

    is_valid_lastname = lastname and len(lastname) <= MAX_LASTNAME_LENGTH
    is_valid_firstname = firstname and len(firstname) <= MAX_FIRSTNAME_LENGTH
    is_valid_email = not g.user.is_admin or (email and len(email) <= MAX_EMAIL_LENGTH)
    is_valid_passphrase = passphrase and MIN_PASSPHRASE_LENGTH <= len(passphrase) <= MAX_PASSPHRASE_LENGTH

    if not is_valid_lastname or not is_valid_firstname or not is_valid_email or not is_valid_passphrase:
        abort(400)

    user.lastname = lastname
    user.firstname = firstname
    if g.user.is_admin:
        user.email = email

    revoke = db.session.is_modified(user)

    db.session.commit()

    try:
        json = {
            'cert_data': session.get('cert_data'),
            'uid': user.uid,
            'lastname': user.lastname,
            'firstname': user.firstname,
            'email': user.email,
            'passphrase': passphrase,
            'revoke': revoke,
        }
        response = requests.post(f'https://{CA_HOST}/issue_certificate', json=json, verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        certificate = base64.b64decode(data['certificate'].encode())
        return send_file(io.BytesIO(certificate), download_name='cert.p12', mimetype='application/x-pkcs12')
    except RuntimeError:
        app.logger.exception('')
        abort(500)


@app.post('/profile/<string:uid>/revoke')
@login_required
def post_revoke(uid):
    if not g.user.is_admin and g.user.uid != uid:
        abort(403)

    user = db.session.get(User, uid)

    if not user:
        abort(404)

    try:
        serial_id_list = [int(item) for item in request.form.getlist('serial_id_list')]
    except:
        abort(400)

    if not serial_id_list:
        abort(400)

    try:
        json = {
            'uid': user.uid,
            'serial_id_list': serial_id_list,
        }
        response = requests.post(f'https://{CA_HOST}/revoke_certificate', json=json, verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        flash('Certificates revoked.', 'info')
        return redirect(url_for('get_profile', uid=user.uid))
    except RuntimeError:
        app.logger.exception('')
        abort(500)


@app.post('/profile/<string:uid>/renew')
@admin_required
def post_renew(uid):
    user = db.session.get(User, uid)

    if not user:
        abort(404)

    if 'cert_data' not in session:
        abort(400)

    passphrase = request.form.get('passphrase')

    is_valid_passphrase = passphrase and MIN_PASSPHRASE_LENGTH <= len(passphrase) <= MAX_PASSPHRASE_LENGTH

    if not is_valid_passphrase:
        abort(400)

    try:
        json = {
            'cert_data': session.get('cert_data'),
            'passphrase': passphrase,
        }
        response = requests.post(f'https://{CA_HOST}/renew_admin_certificate', json=json, verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        flash('Certificate renewed.', 'info')
        session.pop('uid', None)
        session.pop('cert_data', None)
        return redirect(url_for('get_login', next=url_for('get_profile', uid=user.uid)))
    except RuntimeError:
        app.logger.exception('')
        abort(500)


@app.get('/admin')
@admin_required
def get_admin():
    try:
        response = requests.get(f'https://{CA_HOST}/ca_status', verify='/run/secrets/ca_root_cert')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
    except RuntimeError:
        app.logger.exception('')
        data = {}

    users = db.session.query(User).all()

    return render_template('admin.html', data=data, users=users)


@app.get('/logout')
@login_required
def get_logout():
    flash('Logged out.', 'info')
    session.pop('uid', None)
    session.pop('cert_data', None)
    return redirect(url_for('get_login'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
