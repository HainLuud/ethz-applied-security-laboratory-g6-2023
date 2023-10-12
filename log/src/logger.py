#!/usr/bin/env python3

'''
Logger
Authors: 
- Patrick Aldover (paldover@student.ethz.ch)
- Damiano Amatruda (damatruda@student.ethz.ch)
- Alessandro Cabodi (acabodi@student.ethz.ch)
- Hain Luud (haluud@student.ethz.ch)
'''
import traceback
from flask import Flask, jsonify, request
import base64

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Welcome to the Logger interface'

#@app.route('/issue_certificate', methods=['POST'])
#def init():
#    pass

if __name__ == "__main__":
    #context = ('./certs/ca.imovies.ch.crt', './certs/ca.imovies.ch.key')
    app.run(debug=True, host='0.0.0.0', port=9000)#, sslcontext=context)
