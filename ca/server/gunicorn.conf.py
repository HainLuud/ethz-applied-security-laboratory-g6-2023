import os
import socket

LOG_HOST = os.getenv('LOG_HOST')

wsgi_app = 'ca_api:app'
certfile = '/run/secrets/ca-cert'
keyfile = '/run/secrets/ca-key'
bind = '0.0.0.0:8000'
loglevel = 'DEBUG'
logconfig_dict = {
    'version': 1,
    'disable_existing_loggers': False,
    'root': {
        'level': 'DEBUG',
        'handlers': ['console']
    },
    'loggers': {
        'gunicorn.error': {
            'level': 'DEBUG',
            'handlers': ['error_console', 'syslog'],
            'propagate': False,
            'qualname': 'gunicorn.error'
        },
        'gunicorn.access': {
            'level': 'DEBUG',
            'handlers': ['console', 'syslog'],
            'propagate': False,
            'qualname': 'gunicorn.access'
        },
        'ca': {
            'level': 'DEBUG',
            'handlers': ['console', 'syslog'],
            'qualname': 'ca.log'
        }
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'generic',
            'stream': 'ext://sys.stdout'
        },
        'error_console': {
            'class': 'logging.StreamHandler',
            'formatter': 'generic',
            'stream': 'ext://sys.stderr'
        },
        'syslog': {
            'class': 'rfc5424logging.Rfc5424SysLogHandler',
            'formatter': 'simple',
            'address': tuple(LOG_HOST.split(':')),
            'facility': 1,
            'socktype': socket.SOCK_STREAM,
            'tls_enable': True,
            'tls_verify': True,
            'tls_ca_bundle': '/run/secrets/ca-root-cert',
        }
    },
    'formatters': {
        'generic': {
            'format': '%(asctime)s [%(process)d] [%(levelname)s] %(message)s',
            'datefmt': '[%Y-%m-%d %H:%M:%S %z]',
            'class': 'logging.Formatter'
        },
        'simple': {
            'format': '[%(levelname)s] %(message)s',
            'datefmt': '[%Y-%m-%d %H:%M:%S %z]',
            'class': 'logging.Formatter'
        }
    }
}
