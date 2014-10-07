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


