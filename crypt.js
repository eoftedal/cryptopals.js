var crypto = require("crypto");

exports.hexToNum = function(data) {
	var result = [];
	for(var i = 0; i < data.length; i += 2) {
		result.push(parseInt(data[i] + data[i + 1], 16));
	}
	return result;
}

exports.numToHex = function(data) {
	return data.map(function(x) { return (x < 16 ? '0' : '') + x.toString(16); }).join("");
}

exports.numToBase64 = function(data) {
	return new Buffer(data).toString('base64');
}
exports.base64ToNum = function(data) {
	return exports.hexToNum(new Buffer(data, 'base64').toString('hex'));
}

exports.xor = function(num1, num2) {
	return num1.map(function(x, i) { return x ^ num2[i % num2.length]; });
}

exports.numToAscii = function(data) {
	return String.fromCharCode.apply(this, data);
}
exports.asciiToNum = function(data) {
	var result = [];
	for (var i in data) { result.push(data.charCodeAt(i)); }
	return result;
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
		var res = exports.numOfAscii(exports.numToAscii(exports.xor(data, [i])));
		if (res > max) {
			selected = i;
			max = res;
		}
	}
	return { key: selected, result: exports.numToAscii(exports.xor(data, [selected])) };
}

exports.bits = function(data) {
	return data.map(function(n) { return n.toString("2")}).join("").replace(/0/g, "").length;
}

exports.hamm = function(ascii1, ascii2) {
	return exports.bits(exports.xor(ascii1, ascii2));
}

exports.aes256ecb_decrypt = function(datab64, key) {
	var cipher = crypto.createDecipheriv("aes-128-ecb", key, '');
	cipher.setAutoPadding(false);
	var buf = cipher.update(datab64, 'base64');
	buf = Buffer.concat([buf, cipher.final()]);
	return exports.hexToNum(buf.toString('hex'));
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
	var ciph = iv.concat(exports.base64ToNum(data));
	var result = [];
	for (var i = 0; i < data.length; i+= iv.length) {
		result.push(exports.xor(ecb.slice(i, i + iv.length), ciph.slice(i, i + iv.length)));
	}
	return result.map(exports.numToAscii).join("");
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
	return exports.base64ToNum(buf);
}
exports.encryption_oracle_ecb = function(plain) {
	var data = new Buffer(plain).toString('hex') + new Buffer("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK", 'base64').toString('hex');
	//console.log('->' + data);
	//console.log(data.substring(0, 16*2), data.substring(9*16*2, 9*16*2 + 16*2));

	data = exports.hexToNum(data);
	var key = [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5];
	var cipher = crypto.createCipheriv('aes-128-ecb', new Buffer(key), '');
	cipher.setAutoPadding(true);
	var buf = cipher.update(new Buffer(data), null, 'base64');
	buf = buf.concat(cipher.final('base64'));
	return exports.base64ToNum(buf);
}

exports.detect_key_length = function() {
	var plain = [];
	var prev = '';
	var prev2 = '';
	for (var i = 0; i < 20; i++) {
		plain.push("A");
		var cipher = exports.numToHex(exports.encryption_oracle_ecb(exports.asciiToNum(plain.join(""))));
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
			var cipher = exports.numToHex(exports.encryption_oracle_ecb(buf));
			if (cipher.substring(0, length*2) == cipher.substring(cblocks*length*2, cblocks*length*2 + length*2)) {
				result.push(j);
				break;
			}
		}
		console.log(exports.numToAscii(result).replace(/\n/g, '\\n'));
	}
	var pad = result[result.length - 1];
	for (var i = 0; i < pad; i++) {
		result.pop();
	}
	console.log("\nFinal result:\n" + exports.numToAscii(result));
}






