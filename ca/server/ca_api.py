#!/usr/bin/env python3

'''
Certificate Authority - API
Authors:
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''
from flask import Flask, jsonify, request
from flask_talisman import Talisman
import base64
from ca import CA, User

app = Flask(__name__)
Talisman(app)

ca = CA()

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())

@app.route('/')
def hello():
    return 'Welcome to the CA interface'

@app.route('/issue_certificate', methods=['POST'])
def issue_certificate():
    try:
        data = request.json
        user = User.from_dict(data)

        passphrase = data['passphrase'].encode()
        revoke = data['revoke']
        cert = None
        if data['cert_data']:
            cert = data['cert_data'].encode()

        cert = ca.issue_certificate(user, cert, passphrase, revoke)
        cert_b64 = base64.b64encode(cert).decode('utf-8')

        return jsonify({"status": "success", "certificate": cert_b64})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/renew_admin_certificate', methods=['POST'])
def renew_admin_certificate():
    try:
        data = request.json
        passphrase = data['passphrase'].encode()
        cert = None
        if data['cert_data']:
            cert = data['cert_data'].encode()

        ca.renew_admin_certificate(cert, passphrase)

        return jsonify({"status": "success", "message": "Successfully renewed admin certificate. Please contact CA to retrieve the certificate."})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/user_certificates/<string:uid>', methods=['GET'])
def user_certificates(uid):
    try:
        certificates = ca.user_certificates(uid)

        return jsonify({"status": "success", "certificates": certificates})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/user_certificates/<string:uid>/<int:serial_id>', methods=['GET'])
def get_certificate_by_serial_id(uid, serial_id):
    try:
        certificate = ca.get_certificate_by_serial_id(uid, serial_id)

        return jsonify({"status": "success", "certificate": certificate})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/crl', methods=['GET'])
def get_crl():
    try:
        crl = ca.get_crl()
        crl_b64 = base64.b64encode(crl).decode('utf-8')

        return jsonify({"status": "success", "crl": crl_b64})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/revoke_certificate', methods=['POST'])
def revoke_certificate():
    try:
        data = request.json
        uid = data['uid']
        serial_id_list = data['serial_id_list']
        reason = data.get('reason', "unspecified")
        cert = None
        if data['cert_data']:
            cert = data['cert_data'].encode()

        ca.revoke_certificate(uid, cert, serial_id_list, reason)

        return jsonify({"status": "success"})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/ca_status', methods=['GET'])
def get_ca_status():
    try:
        n_issued, n_revoked, next_serial_id, backup_status = ca.get_status()

        return jsonify({"status": "success", "n_issued": n_issued, "n_revoked": n_revoked, "next_serial_id": next_serial_id, "backup_status": backup_status})

    except Exception as e:
        app.logger.exception('')
        return jsonify({"status": "error", "message": str(e)}), 400


if __name__ == "__main__":
    context = ('/run/secrets/ca_cert', '/run/secrets/ca_key')
    app.run(debug=True, host='0.0.0.0', port=8000, sslcontext=context)
