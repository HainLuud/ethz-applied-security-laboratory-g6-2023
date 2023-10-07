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
import base64
from ca import CA
from user import User

app = Flask(__name__)

ca = CA()

@app.route('/')
def hello():
    return 'Welcome to the CA interface'

@app.route('/issue_certificate', methods=['POST'])
def issue_certificate():
    try:
        data = request.json
        uid = data['uid']
        lastname = data['lastname']
        firstname = data['firstname']
        email = data['email']
        user = User(uid, lastname, firstname, email)
        
        passphrase = data['passphrase'].encode()
        
        cert = ca.issue_certificate(user, passphrase)
        cert_b64 = base64.b64encode(cert).decode('utf-8')

        return jsonify({"status": "success", "certificate": cert_b64})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/user_certificates/<uid>', methods=['GET'])
def user_certificates(uid):
    try:
        certificates = ca.user_certificates(uid)

        return jsonify({"status": "success", "certificates": certificates})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/revoke_certificate', methods=['POST'])
def revoke_certificate():
    try:
        data = request.json
        uid = data['uid']
        serial_id_list = data['serial_id_list']
        reason = data.get('reason', "unspecified")
        
        ca.revoke_certificate(uid, serial_id_list, reason)
        
        return jsonify({"status": "success"})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/ca_status', methods=['GET'])
def get_ca_status():
    try:
        n_issued, n_revoked, next_serial_id = ca.get_status()
        
        return jsonify({"status": "success", "n_issued": n_issued, "n_revoked": n_revoked, "next_serial_id": next_serial_id})
    
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=8000)
