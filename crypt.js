var crypto = require("crypto");

String.prototype.hexDecode = function() {
	return this.match(/../g).map(function(n) { return parseInt(n, 16); });
}


Array.prototype.hexEncode = function() {
	return this.map(function(x) { return (x < 16 ? '0' : '') + x.toString(16); }).join("");
}
Array.prototype.base64Encode = function() {
	return new Buffer(this).toString('base64');
}
String.prototype.base64Decode = function() {
	return new Buffer(data, 'base64').toString('hex').hexDecode();
}
Array.prototype.xor = function(num) {
	return this.map(function(x, i) { return x ^ num[i % num.length]; });
}
Array.prototype.toAscii = function() {
	return String.fromCharCode.apply(String, data);
}
String.prototype.toByteArray = function() {
	return this.match(/./g).map(function(c) { return c.charCodeAt(0) });
}


exports.numOfAscii = function(data) {
	return data.split(/[a-zA-Z ]/).length
}

exports.solveSingleCharacterXor = function(data) {
	return exports.solveSingleCharacterXorWithKey(data).result;
}
exports.solveSingleCharacterXorWithKey = function(data) {
	var max = -1;
	var selected = -1;
	for(var i = 0; i < 256; i++) {
		var res = exports.numOfAscii(data.xor([i]).toAscii())
		if (res > max) {
			selected = i;
			max = res;
		}
	}
	return { key: selected, result: data.xor([selected]).toAscii() };
}

exports.bits = function(data) {
	return data.map(function(n) { return n.toString("2")}).join("").replace(/0/g, "").length;
}

exports.hamm = function(ascii1, ascii2) {
	return exports.bits(ascii1.xor(ascii2));
}

exports.aes256ecb_decrypt = function(datab64, key) {
	var cipher = crypto.createDecipheriv("aes-128-ecb", key, '');
	cipher.setAutoPadding(false);
	var buf = cipher.update(datab64, 'base64');
	buf = Buffer.concat([buf, cipher.final()]);
	return buf.toString('hex').hexDecode();
}

exports.aes256ecb_encrypt = function(data, key) {
	var cipher = crypto.createCipheriv("aes-128-ecb", key, '');
	cipher.setAutoPadding(false);
	var result = cipher.update(data, 'binary', 'binary');
	result = result.concat(cipher.final('binary'));
	return result.toString('hex');
}

exports.pkcs7pad = function(data, length) {
	var padlen = length - (data.length % length);
	var result = data.slice(0);
	for (var i = 0; i < padlen; i++) result.push(padlen);
	return result;
}

exports.cbcDecrypt = function(data, key, iv) {
	var ecb = exports.aes256ecb_decrypt(data, key);
	var ciph = iv.concat(data.base64Decode());
	var result = [];
	for (var i = 0; i < data.length; i+= iv.length) {
		result.push(ecb.slice(i, i + iv.length).xor(ciph.slice(i, i + iv.length)));
	}
	return result.map(function(x) { return x.toAscii() }).join("");
}
exports.generateKey = function(length) {
	return crypto.randomBytes(length);
}

exports.encryption_oracle = function(plain) {
	var pre = crypto.randomBytes(crypto.randomBytes(1)[0] % 5 + 5);
	var post = crypto.randomBytes(crypto.randomBytes(1)[0] % 5 + 5);
	var data = Buffer.concat([pre, new Buffer(plain), post]);
	var key = exports.generateKey(16);
	var cbc = crypto.randomBytes(1)[0] < 128;
	var iv = '';
	var algo = 'aes-128-ecb';
	if (cbc) {
		iv = crypto.randomBytes(16);
		algo = 'aes-128-cbc';
	}
	console.log("Actual  : " + (cbc ? "CBC" : "ECB"));
	var cipher = crypto.createCipheriv(algo, key, iv);
	cipher.setAutoPadding(true);
	var buf = cipher.update(new Buffer(data), null, 'base64');
	buf = buf.concat(cipher.final('base64'));
	return buf.base64Decode();
}

exports.encryption_oracle_ecb = function(plain) {
	var data = new Buffer(plain).toString('hex') + new Buffer("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK", 'base64').toString('hex');
	//console.log('->' + data);
	//console.log(data.substring(0, 16*2), data.substring(9*16*2, 9*16*2 + 16*2));

	data = data.hexDecode();
	var key = [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5];
	var cipher = crypto.createCipheriv('aes-128-ecb', new Buffer(key), '');
	cipher.setAutoPadding(true);
	var buf = cipher.update(new Buffer(data), null, 'base64');
	buf = buf.concat(cipher.final('base64'));
	return buf.base64Decode();
}

exports.detect_key_length = function() {
	var plain = [];
	var prev = '';
	var prev2 = '';
	for (var i = 0; i < 20; i++) {
		plain.push("A");
		var cipher = exports.encryption_oracle_ecb(plain.join("").toByteArray()).hexEncode();
		if(prev2 && prev) {
			for (var j = 2; j < 20; j++) {
				if (prev.substring(0, j) == prev2.substring(0, j) && cipher.substring(0, j) == prev.substring(0, j)) {
					return i - 1;
				}
			}
		}
		prev2 = prev;
		prev = cipher;
	}
}
exports.oracle_decrypt = function(length) {
	var cipherlen = exports.encryption_oracle_ecb("").length;
	var result = [];
	var cblocks = Math.ceil(cipherlen/length);
	for(var i = 0; i < cipherlen; i++) {
		var blocks = Math.floor(result.length / length) + 1;
		var buf = new Buffer(length + cblocks * length - 1 - result.length);
		buf.fill('A');
		var c = 0;
		for (var k = result.length; k >= 0; k--) {
			buf[length - ++c] = result[k];
			if (c == length) break;
		}
		for(var j = 0; j < 256; j++) {
			buf[15] = j;
			var cipher = exports.encryption_oracle_ecb(buf).hexEncode();
			if (cipher.substring(0, length*2) == cipher.substring(cblocks*length*2, cblocks*length*2 + length*2)) {
				result.push(j);
				break;
			}
		}
		console.log(result.toAscii().replace(/\n/g, '\\n'));
	}
	var pad = result[result.length - 1];
	for (var i = 0; i < pad; i++) {
		result.pop();
	}
	console.log("\nFinal result:\n" + result.toAscii());
}

exports.parseParameters = function(x) {
	var obj = {};
	x.split(/&/g).forEach(function(n) {  
		var ar = n.split(/=/);
		obj[ar[0]] = ar[1];
	});
	return obj;
}

exports.profile_for = function(email) {
	var obj = { email: email.replace(/[&=]/g, ""), uid: 10, role: 'user'};
	var res = "";
	var delim = "";
	for (var i in obj) {
		res += delim + i + "=" + obj[i];
		delim = "&";
	}
	return res;
}




