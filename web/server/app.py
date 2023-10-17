#!/usr/bin/env python3

import base64
from datetime import timedelta
import hashlib
import io
import os
import re
import traceback
import urllib.parse
from functools import wraps

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from flask import (Flask, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy

DATABASE_DB = os.getenv('DATABASE_DB')
DATABASE_USER = os.getenv('DATABASE_USER')
DATABASE_PASSWORD_FILE = os.getenv('DATABASE_PASSWORD_FILE')
with open(DATABASE_PASSWORD_FILE, 'r') as f:
    DATABASE_PASSWORD = f.read().strip()
DATABASE_HOST = os.getenv('DATABASE_HOST')
WEB_SECRET_KEY_FILE = os.getenv('WEB_SECRET_KEY_FILE')
with open(WEB_SECRET_KEY_FILE, 'r') as f:
    WEB_SECRET_KEY = f.read().strip()
CA_HOST = os.getenv('CA_HOST')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{DATABASE_DB}'
app.config['SECRET_KEY'] = WEB_SECRET_KEY
db = SQLAlchemy(app, engine_options={
    'connect_args': {
        'ssl_verify_identity': True,
        'ssl_ca': '/etc/ssl/certs/root.imovies.ch.crt',
    }
})


class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'MyISAM'}

    uid = db.Column(db.String(64), primary_key=True)
    lastname = db.Column(db.String(64), nullable=False)
    firstname = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    pwd = db.Column(db.String(64), nullable=False)

    def is_admin(self) -> str:
        return self.uid == 'admin'

    @staticmethod
    def hash_pwd(pwd: str) -> str:
        return hashlib.sha256(pwd.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            flash('You need to log in first.', 'error')
            return redirect(url_for('get_login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user:
            flash('You need to log in first.', 'error')
            return redirect(url_for('get_login', next=request.path))
        if not g.user.is_admin():
            flash('You do not have permission to access the page.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)


@app.before_request
def load_user():
    g.user = db.session.get(User, session['uid']) if 'uid' in session else None


@app.errorhandler(404)
def not_found(e):
    return render_template('not_found.html'), 404


@app.get('/')
@login_required
def index():
    return render_template('index.html')


@app.get('/crl')
@login_required
def get_crl():
    try:
        response = requests.get(f'https://{CA_HOST}/crl', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
        crl = base64.b64decode(data['crl'].encode())
        return send_file(io.BytesIO(crl), download_name='crl.pem', mimetype='application/x-pem-file')
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')
        return redirect(url_for('index'))


@app.get('/login')
def get_login():
    next = request.args.get('next')
    has_cert = 'HTTP_X_SSL_CERT' in request.environ
    if not next:
        return redirect(url_for('get_login', next=url_for('index')))
    return render_template('login.html', next=next, has_cert=has_cert)


@app.post('/login')
def post_login():
    uid = request.form.get('uid')
    pwd = request.form.get('pwd')
    next = request.form.get('next', url_for('index'))

    if not uid or not pwd:
        flash('You must specify user ID and password.', 'error')
        return redirect(url_for('get_login', next=next))

    user = db.session.get(User, uid)

    if not user or User.hash_pwd(pwd) != user.pwd:
        flash('Wrong user ID or password.', 'error')
        return redirect(url_for('get_login', next=next))

    flash('Successful login.', 'info')
    session['uid'] = user.uid
    return redirect(next)


@app.get('/login_cert')
def get_login_cert():
    next = request.form.get('next', url_for('index'))
    cert_data = request.environ.get('HTTP_X_SSL_CERT')

    if not cert_data:
        flash('You must specify a certificate.', 'error')
        return redirect(url_for('get_login', next=next))
    
    cert = x509.load_pem_x509_certificate(urllib.parse.unquote(cert_data).encode())
    try:
        commonname = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except:
        flash('Certificate processing error.', 'error')
        return redirect(url_for('get_login', next=next))

    match = re.search(r'(?P<uid>.*)\.imovies\.ch', commonname)
    if not match:
        flash('Wrong certificate.', 'error')
        return redirect(url_for('get_login', next=next))

    uid = match.group('uid')
    serial_id = cert.serial_number

    try:
        response = requests.get(f'https://{CA_HOST}/user_certificates/{uid}/{serial_id}', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()

        if data['status'] != 'success':
            raise Exception(data['message'])

        certificate = data['certificate']

        if certificate['revoked']:
            flash('The certificate was revoked.', 'error')
            return redirect(url_for('get_login', next=next))

        user = db.session.get(User, uid)

        if not user:
            user = User(uid=uid, lastname=certificate['lastname'], firstname=certificate['firstname'], email=certificate['email'], pwd='')
            db.session.add(user)
            db.session.commit()

        flash('Successful login.', 'info')
        session['uid'] = user.uid
        return redirect(next)
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')
        return redirect(url_for('get_login', next=next))


@app.get('/profile/', defaults={'uid': None})
@app.get('/profile/<string:uid>')
@login_required
def get_profile(uid):
    if not uid:
        return redirect(url_for('get_profile', uid=g.user.uid))

    if not g.user.is_admin() and g.user.uid != uid:
        flash('You do not have permission to access the page.', 'error')
        return redirect(url_for('index'))

    user = db.session.get(User, uid)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('index'))

    try:
        response = requests.get(f'https://{CA_HOST}/user_certificates/{user.uid}', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
        certificates = data['certificates']
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')
        certificates = None

    return render_template('profile.html', user=user, certificates=certificates)


@app.post('/profile/<string:uid>/change_password')
@login_required
def post_change_password(uid):
    if not g.user.is_admin() and g.user.uid != uid:
        flash('You do not have permission to access the page.', 'error')
        return redirect(url_for('index'))

    user = db.session.get(User, uid)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('index'))

    pwd = request.form.get('pwd')
    pwd2 = request.form.get('pwd2')

    if not pwd or not pwd2:
        flash('Invalid information.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    if pwd != pwd2:
        flash('The input passwords are not equal.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    user.pwd = User.hash_pwd(pwd)

    db.session.commit()

    flash('Password changed.', 'info')
    return redirect(url_for('get_profile', uid=user.uid))


@app.post('/profile/<string:uid>/issue')
@login_required
def post_issue(uid):
    if (g.user.is_admin() and g.user.uid == uid) or (not g.user.is_admin() and g.user.uid != uid):
        flash('You do not have permission to access the page.', 'error')
        return redirect(url_for('index'))

    user = db.session.get(User, uid)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('index'))

    lastname = request.form.get('lastname')
    firstname = request.form.get('firstname')
    email = request.form.get('email')
    passphrase = request.form.get('passphrase')

    if not all(v for v in (lastname, firstname, email)):
        flash('Invalid information.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    user.lastname = lastname
    user.firstname = firstname
    user.email = email

    revoke = db.session.is_modified(user)

    db.session.commit()

    try:
        json = {
            'uid': user.uid,
            'lastname': user.lastname,
            'firstname': user.firstname,
            'email': user.email,
            'passphrase': passphrase,
            'revoke': revoke,
        }
        response = requests.post(f'https://{CA_HOST}/issue_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
        certificate = base64.b64decode(data['certificate'].encode())
        return send_file(io.BytesIO(certificate), download_name='cert.p12', mimetype='application/x-pkcs12')
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))


@app.post('/profile/<string:uid>/revoke')
@login_required
def post_revoke(uid):
    if not g.user.is_admin() and g.user.uid != uid:
        flash('You do not have permission to access the page.', 'error')
        return redirect(url_for('index'))

    user = db.session.get(User, uid)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    try:
        serial_id_list = [int(item) for item in request.form.getlist('serial_id_list')]
    except:
        flash('Invalid serial ID.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    if not serial_id_list:
        flash('You must specify serial IDs.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    if not g.user.is_admin() and g.user.uid != uid:
        flash('You do not have permission to access the page.', 'error')
        return redirect(url_for('index'))

    try:
        json = {
            'uid': user.uid,
            'serial_id_list': serial_id_list,
        }
        response = requests.post(f'https://{CA_HOST}/revoke_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
        flash('Certificates revoked.', 'info')
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')

    return redirect(url_for('get_profile', uid=user.uid))


@app.post('/profile/<string:uid>/renew')
@admin_required
def post_renew(uid):
    user = db.session.get(User, uid)

    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('get_profile', uid=user.uid))

    passphrase = request.form.get('passphrase')

    try:
        json = {
            'passphrase': passphrase,
        }
        response = requests.post(f'https://{CA_HOST}/renew_admin_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
        flash('Certificate renewed.', 'info')
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')

    return redirect(url_for('get_profile', uid=user.uid))


@app.get('/admin')
@admin_required
def get_admin():
    try:
        response = requests.get(f'https://{CA_HOST}/ca_status', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise Exception(data['message'])
    except Exception:
        traceback.print_exc()
        flash('An error occurred while contacting the CA.', 'error')
        data = {}

    users = db.session.query(User).all()

    return render_template('admin.html', data=data, users=users)


@app.get('/logout')
@login_required
def get_logout():
    session.pop('uid', None)
    flash('You logged out.', 'info')
    return redirect(url_for('get_login'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
