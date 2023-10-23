#!/usr/bin/env python3

import base64
import io
import os
import re
import traceback
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

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+mysqlconnector://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}/{DATABASE_DB}'
app.config['SECRET_KEY'] = WEB_SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = WEB_CSRF_SECRET_KEY
db = SQLAlchemy(app, engine_options={
    'connect_args': {
        'auth_plugin': 'caching_sha2_password',
        'ssl_verify_identity': True,
        'ssl_ca': '/etc/ssl/certs/root.imovies.ch.crt',
    }
})
csrf = CSRFProtect(app)


class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'mysql_engine': 'MyISAM'}

    uid = db.Column(db.String(64), primary_key=True)
    lastname = db.Column(db.String(64), nullable=False)
    firstname = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    pwd = db.Column(db.String(64), nullable=False)

    @property
    def is_admin(self) -> str:
        return self.uid == 'admin'

    @property
    def name(self) -> str:
        if self.firstname and self.lastname:
            name = f'{self.firstname} {self.lastname}'
        elif self.firstname:
            name = self.firstname
        elif self.lastname:
            name = self.lastname
        else:
            name = self.uid
        return render_template_string(name)

    def update_pwd(self, pwd: str) -> str:
        return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())

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
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)


@app.before_request
def load_user():
    g.user = db.session.get(User, session['uid']) if 'uid' in session else None


@app.errorhandler(400)
def handle_csrf_error(e):
    return render_template('error.html', code=400, title='Bad Request', message='Invalid request.'), 400


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, title='Forbidden', message='Permission denied.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, title='Page Not Found', message='Could not find the requested page.'), 404


@app.errorhandler(500)
def not_found(e):
    return render_template('error.html', code=500, title='Internal Server Error', message='The server encountered an internal error.'), 500


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
            raise RuntimeError(data['message'])
        crl = base64.b64decode(data['crl'].encode())
        return send_file(io.BytesIO(crl), download_name='crl.pem', mimetype='application/x-pem-file')
    except RuntimeError:
        traceback.print_exc()
        abort(500)


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
    next = '/' + request.form.get('next', url_for('index')).lstrip('/')

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
        response = requests.get(f'https://{CA_HOST}/user_certificates/{uid}/{serial_id}', verify='/etc/ssl/certs/root.imovies.ch.crt')
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
        traceback.print_exc()
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
        response = requests.get(f'https://{CA_HOST}/user_certificates/{user.uid}', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        certificates = data['certificates']
    except RuntimeError:
        traceback.print_exc()
        certificates = None

    return render_template('profile.html', user=user, certificates=certificates)


@app.post('/profile/<string:uid>/change_password')
@login_required
def post_change_password(uid):
    if not g.user.is_admin and g.user.uid != uid:
        abort(403)

    user = db.session.get(User, uid)

    if not user:
        abort(404)

    pwd = request.form.get('pwd')
    pwd2 = request.form.get('pwd2')

    if not pwd or not pwd2:
        abort(400)

    if pwd != pwd2:
        flash('The passwords provided are different.', 'error')
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

    if not lastname or not firstname or not email:
        abort(400)

    user.lastname = lastname
    user.firstname = firstname
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
        response = requests.post(f'https://{CA_HOST}/issue_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        certificate = base64.b64decode(data['certificate'].encode())
        return send_file(io.BytesIO(certificate), download_name='cert.p12', mimetype='application/x-pkcs12')
    except RuntimeError:
        traceback.print_exc()
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
        response = requests.post(f'https://{CA_HOST}/revoke_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        flash('Certificates revoked.', 'info')
        return redirect(url_for('get_profile', uid=user.uid))
    except RuntimeError:
        traceback.print_exc()
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

    try:
        json = {
            'cert_data': session.get('cert_data'),
            'passphrase': passphrase,
        }
        response = requests.post(f'https://{CA_HOST}/renew_admin_certificate', json=json, verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
        flash('Certificate renewed.', 'info')
        return redirect(url_for('get_profile', uid=user.uid))
    except RuntimeError:
        traceback.print_exc()
        abort(500)


@app.get('/admin')
@admin_required
def get_admin():
    try:
        response = requests.get(f'https://{CA_HOST}/ca_status', verify='/etc/ssl/certs/root.imovies.ch.crt')
        data = response.json()
        if data['status'] != 'success':
            raise RuntimeError(data['message'])
    except RuntimeError:
        traceback.print_exc()
        data = {}

    users = db.session.query(User).all()

    return render_template('admin.html', data=data, users=users)


@app.get('/logout')
@login_required
def get_logout():
    session.pop('uid', None)
    session.pop('cert_data', None)
    flash('Logged out.', 'info')
    return redirect(url_for('get_login'))


with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
