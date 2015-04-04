#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import AES
from bottle import bottle

@bottle.route('/jdcheck.js', method = 'get')
def jdcheck():
	return "jdownloader=true; var version='17461';"

@bottle.route('/flash/addcrypted2', method = 'post')
def clicknload2():
	password = bottle.request.forms.get("passwords")
	source = bottle.request.forms.get("source")
	jk = bottle.request.forms.get("jk")
	crypted = bottle.request.forms.get("crypted")

	urls = decrypt_clicknload2(crypted, jk)
	for u in urls: print(u)

def decrypt_clicknload2(eaw_crypted, raw_jk):
	decrypt = aes_decrypt(eaw_crypted, extract_jk(raw_jk))
	return get_urls(decrypt)

def get_urls(enc_crypt):
	return [result for result in enc_crypt.decode("utf-8").replace('\x00', '').split("\r\n") if len(result) > 0]

def extract_jk(jk):
	i1 = jk.index("'") + 1
	i2 = jk.index("'", i1)
	return base64.b16decode(jk[i1:i2])

def aes_decrypt(enc, key):
	cipher = AES.new(key, AES.MODE_CBC, key)
	return cipher.decrypt(base64.b64decode(enc))

if __name__ == "__main__":
	bottle.run(host='127.0.0.1', port=9666, debug=False)
