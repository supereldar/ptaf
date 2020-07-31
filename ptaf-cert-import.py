#!/opt/waf/python/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import hashlib
import argparse
import subprocess
from pymongo import MongoClient, errors
from bson import Binary, ObjectId


def parse_cli_args():
    parser = argparse.ArgumentParser(description='Letsencrypt integration')
    parser.add_argument('--host',
                        dest='host',
                        required=True,
                        help='Hostname for certificate')
    args = parser.parse_args()
    return args


def colorize(color, text):
    if color == 'red':
        return ''.join(['\033[1;31m', text, '\033[1;m'])
    elif color == 'green':
        return ''.join(['\033[1;32m', text, '\033[1;m'])
    elif color == 'blue':
        return ''.join(['\033[1;34m', text, '\033[1;m'])
    else:
        return text


def fileUpload(db, ssl_file, ssl_type, host):
    if ssl_type == "key":
        filename = "{}.{}".format(host, "key")
        path = "/opt/waf/conf/ssl/keys"
    else:
        filename = "{}.{}".format(host, "crt")
        path = "/opt/waf/conf/ssl/certificates"

    found = db.ssl.files.find_one({"filename": filename})
    if found and "_id" in found:
        db.ssl.files.update({"filename": filename},
                            {"$set": {"md5": hashlib.md5(ssl_file).hexdigest(), "length": len(ssl_file)}})
        db.ssl.chunks.update({"files_id": ObjectId(found["_id"])},
                             {"$set": {"data": Binary(ssl_file, 0)}})
        file_id = found["_id"]
        print(colorize("green", "[+] File {} updated".format(filename)))
    else:
        file_id = db.ssl.files.insert_one(
            {
                "filename": filename,
                "chunkSize": 261120,
                "length": len(ssl_file),
                "md5": hashlib.md5(ssl_file).hexdigest(),
                "metadata": {
                    "path": path,
                    "is_dir": False}}).inserted_id
        db.ssl.chunks.insert_one(
            {"n": 0, "data": Binary(ssl_file, 0), "files_id": file_id})
        print(colorize("green", "[+] File {} added to DB".format(filename)))
    return file_id


def sslSettings(db, cert_id, key_id, host):
    found = db.ssl.find_one({"name": host})
    if found and "_id" in found:
        db.ssl.update({"name": host},
                      {"$set": {"certificate": ObjectId(cert_id),
                                "certificate_key": ObjectId(key_id)}})
        print(colorize("green", "[+] SSL Settings {} updated".format(host)))
    else:
        ciphers = ('ECDH+AESGCM:DH+AESGCM:'
                   'ECDH+AES256:DH+AES256:'
                   'ECDH+AES128')
        db.ssl.insert_one(
            {
                "prefer_server_ciphers": True,
                "name": host,
                "certificate": ObjectId(cert_id),
                "ciphers": ciphers,
                "certificate_key": ObjectId(key_id),
                "protocols": [
                    "TLSv1",
                    "TLSv1.1",
                    "TLSv1.2"],
                "signature_algorithm": "RSA",
                "crl": None,
                "client_certificate": None})
        print(
            colorize(
                "green",
                "[+] SSL Settings {} added to DB".format(host)))


def cmdExecute(command):
    return subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)


def main():
    if not os.geteuid() == 0:
        print(colorize("red", "[!] ERROR: This script must be run as root"))
        sys.exit()
    args = parse_cli_args()
    process = cmdExecute(["wsc -c 'cluster list mongo' | grep 'mongodb://' | awk '{print $2}'"])
    mongo_uri = process.stdout.readline().strip()
    client = MongoClient(mongo_uri)
    print(colorize("green", "[+] Connected to {}".format(mongo_uri)))
    db = client.waf
    path = "/root/.acme.sh/{}".format(args.host)
    key = open("{}/{}.key".format(path,args.host)).read()
    cert = open("{}/fullchain.cer".format(path)).read()
    key_id = fileUpload(db, key, "key", args.host)
    cert_id = fileUpload(db, cert, "crt", args.host)
    sslSettings(db, cert_id, key_id, args.host)
    status = cmdExecute(["service waf-sync restart"])
    print(colorize("green", "[+] waf-sync restarted"))
    status = cmdExecute(["service waf-nginx reload"])
    print(colorize("green", "[+] waf-nginx reloaded"))
    status = cmdExecute(["service nginx reload"])
    print(colorize("green", "[+] nginx reloaded"))

if __name__ == '__main__':
    main()
