import argparse
import pickle
import socket
import sys
import gzip
from io import BytesIO
from hashlib import md5
import json

from flask import Flask, request, jsonify
from flask_cors import CORS
from gevent import pywsgi

from monte_carlo_lib import MonteCarloLib

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*"}})

dangerous_chunks = pickle.load(open("resources/dangerous_chunks.pickle", 'rb'))
monte_carlo = pickle.load(open("resources/monte_carlo.pickle", 'rb'))
pcfg_model = json.loads(pickle.load(open("resources/ckl_pcfg_model.pickle", 'rb')))
encode_dangerous_chunks=[md5(x.encode("utf8")).hexdigest() for x in dangerous_chunks]

def gzip_wrapper(response, compress_level=6):
    gzip_buffer = BytesIO()
    gzip_file = gzip.GzipFile(mode='wb', compresslevel=compress_level, fileobj=gzip_buffer)
    gzip_file.write(response.get_data())
    gzip_file.close()
    response.set_data(gzip_buffer.getvalue())
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(response.get_data())
    return response

@app.route('/pcfgmodel', methods=['get'])
def model_handler():
    return gzip_wrapper(jsonify(pcfg_model))

@app.route('/pcfgrank', methods=['get'])
def rank_handler():
    resp = monte_carlo.to_dict()
    resp["blocklist"] = encode_dangerous_chunks
    return gzip_wrapper(jsonify(resp))

def get_host_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        if s is not None:
            s.close()
    return ip


def wrapper():
    ip = get_host_ip()
    cli = argparse.ArgumentParser("BPE Password Strength Meter")
    cli.add_argument("--ip", type=str, default=f"{ip}", help="Specify the ip, e.g., localhost")
    cli.add_argument("--port", type=int, default=3001, help="Specify the port, e.g., 3000")
    args = cli.parse_args()
    server = pywsgi.WSGIServer((args.ip, args.port), app, log=sys.stdout)
    server.log.write(f"http://{args.ip}:{args.port}/\n")
    server.log.flush()
    server.serve_forever()


if __name__ == '__main__':
    try:
        wrapper()
    except KeyboardInterrupt:
        sys.exit("Exit")
