var crypto = require("crypto");

String.prototype.hexDecode = function() {
	return this.match(/../g).map(function(n) { return parseInt(n, 16); });
}

Array.prototype.hexEncode = function() {
	return this.map(function(x) { return (x < 16 ? '0' : '') + x.toString(16); }).join("");
}
Array.prototype.base64Encode = function() {
	return new Buffer(this.slice()).toString('base64');
}
String.prototype.base64Decode = function() {
	return new Buffer(this.toString(), 'base64').toString('hex').hexDecode();
}
Array.prototype.xor = function(num) {
	return this.map(function(x, i) { return x ^ num[i % num.length]; });
}
Array.prototype.toAscii = function() {
	return String.fromCharCode.apply(String, this);
}
String.prototype.toByteArray = function() {
	return this.match(/[\s\S]/g).map(function(c) { return c.charCodeAt(0) });
}
Array.randomBytes = function(n) {
	return Array.prototype.slice.apply(crypto.randomBytes(n));
}
Array.of = function(n, c) {
	var a = [];
	for (var i = 0; i < n; i++) a.push(c);
	return a;
}
String.prototype.toByte = function() {
	return this.charCodeAt(0);
}

exports.paddingValid = function(n) {
	var a = n.toByteArray();
	var p = a[a.length - 1];
	for (var i = 1; i <= p; i++) {
		if (a[a.length - i] != p) return false;
	}
	return true;
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
		//console.log(max, res, i);
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

exports.aes256ecb_decrypt = function(data, key) {
	var cipher = crypto.createDecipheriv("aes-128-ecb", new Buffer(key), '');
	cipher.setAutoPadding(false);
	var buf = cipher.update(new Buffer(data), 'base64');
	buf = Buffer.concat([buf, cipher.final()]);
	return buf.toString('hex').hexDecode();
}

exports.aes256ecb_encrypt = function(data, key) {
	var cipher = crypto.createCipheriv("aes-128-ecb", new Buffer(key), '');
	cipher.setAutoPadding(false);
	var result = cipher.update(new Buffer(data), 'binary', 'hex');
	result += cipher.final('hex');
	return result;
}

exports.pkcs7pad = function(data, length) {
	var padlen = length - (data.length % length);
	var result = data.slice(0);
	for (var i = 0; i < padlen; i++) result.push(padlen);
	return result;
}

exports.cbcDecrypt = function(data, key, iv) {
	var ecb = exports.aes256ecb_decrypt(data, new Buffer(key));
	var ciph = iv.concat(data);
	var result = [];
	for (var i = 0; i < data.length; i+= iv.length) {
		result.push(ecb.slice(i, i + iv.length).xor(ciph.slice(i, i + iv.length)));
	}
	return result.map(function(x) { return x.toAscii() }).join("");
}
exports.cbcEncrypt = function(data, key, iv) {
	var pblock = new Buffer(iv);
	var result = new Buffer([]);
	for (var i = 0; i < data.length; i  += iv.length) {
		var b = data.slice(i, i+iv.length).xor(Array.prototype.slice.apply(pblock));
		var pblock = new Buffer(exports.aes256ecb_encrypt(b, key), 'hex');
		result = Buffer.concat([result, pblock]);
	}
	return result.toString('base64');
}
exports.padAndCbcEncrypt = function(data, key, iv) {
	return exports.cbcEncrypt(exports.pkcs7pad(data, 16), key, iv);
}
exports.cbcDecryptAndRemovePadding = function(cipher, key, iv) {
	var a = exports.cbcDecrypt(cipher, key, iv).toByteArray();
	var pad = a[a.length - 1];
	if (pad == 0 || pad > 16) throw new Error("Invalid padding");
	for (var i = 1; i <= pad; i++) {
		if (a[a.length - 1] == pad) {
			a.pop();
		} else {
			throw new Error("Invalid padding");
		}
	}
	return a;
}

exports.toLittleEndian = function(num) {
	var l = num.toString(16);
	if (l.length % 2 == 1) l = "0" + l;
	var k = l.hexDecode();
	k.reverse();
	return k;
}


exports.aesctr = function(key, nonce, data) {
	var blocks = Math.ceil(data.length/16);
	var stream = [];
	for (var i = 0; i < blocks; i++) {
		var d = nonce.concat(exports.toLittleEndian(i));
		for (var m = d.length; m < 16; m++) {
			d.push(0);
		}
		stream = stream.concat(exports.aes256ecb_encrypt(d, key).hexDecode());
	}
	return stream.slice(0, data.length).xor(data);
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

exports.mtCrypt = function(key, data) {
	var rnd = new exports.MersenneTwister(key);
	var cipher = [];
	var k;
	var j = 0;
	for (var i = 0; i < data.length; i++) {
		if (j == 0) k = rnd.next();
		cipher[i] = data[i] ^ ((k >>> (i*8)) & 0xff);
		j = (j+1) % 4;
	}
	return cipher;
}

exports.MersenneTwister = function(seed) {
	var w = 32,n = 624 ,m = 397, r = 31;
	var u = 11, d =	0xFFFFFFFF;
	var s = 7, b = 0x9D2C5680;
	var t = 15, c = 0xEFC60000;
	var l = 18;
	var a = 0x9908B0DF;
	var lower_mask = 0x7fffffff;;
	var upper_mask = 0x80000000;
	var f = 1812433253;

	var mt = new Uint32Array(n);
	mt.fill(0);
	var index = n;

	index = n;
  mt[0] = seed >>> 0;
  for (var i = 1; i < n; i++) { // loop over each element
  	var ss = mt[i-1] ^ (mt[i-1] >>> w-2);
    mt[i] = ((((((ss & 0xffff0000) >>> 16) * f) << 16) + (ss & 0x0000ffff) * f) + i) >>> 0;
  }

	function twist() {
	   for(var i = 0; i < n; i++) {
       var x = (mt[i] & upper_mask) + (mt[(i+1) % n] & lower_mask) >>> 0
       mt[i] = mt[(i + m) % n] ^ x >>> 1

       if ((x % 2) != 0) { // lowest bit of x is 1
           mt[i] = mt[i] ^ a
       }
	   }
	   index = 0;
	}
	function sl(x, sh) {
		return x * Math.pow(2, sh);
	}
	function next() {
		if (index >= n) twist();
		y = mt[index++];
		return temper(y);
	}
	function temper(y) {
		y = (y ^ (y >>> u)) >>> 0;
		y = (y ^ (sl(y, s) & b)) >>> 0;
		y = (y ^ (sl(y, t) & c)) >>> 0;
		y = (y ^ (y >>> l)) >>> 0;
		return y;		
	}


	function untemper(y) {
		y = ((y >>> l) ^ y) >>> 0; //the l=18 first bits are unaffected by the xor, so we can "fix"
															// the top 14 by doing xor again
		y = (y ^ (sl(y , t) & c)) >>> 0; // Only the top 16 bits can be affected because the first 16 bits
									//of c are all 0. Thus we can just redo this operation even though we only shift 
									// t=15 places  
		var x = y;
		//the original operation leaves the first 7 bits unaffected, so we can fix the next 7 bits by redoing
		y = (x ^ (sl(y, s) & b)) >>> 0;
		//now that the 14 first bits are back, we can redo to fix the next 7 
		y = (x ^ (sl(y, s) & b)) >>> 0;
		//21 are now correct and we redo to fix the next 7
		y = (x ^ (sl(y, s) & b)) >>> 0;
		//28 are now ok so we redo to fix the last 4
		y = (x ^ (sl(y, s) & b)) >>> 0; 
		x = y;
		//We have to do this twice to first fix bits 12-22
		y = (x ^ ((y >>> 11))) >>> 0;
		//and then fix 23-32
		y = (x ^ ((y >>> 11))) >>> 0;
		return y;
	}
	function setState(state) {
		state.forEach((x,i) => mt[i] = x);
	}

	return {
		next,
		temper,
		untemper,
		setState
	}


}

exports.passwordResetTokenMT = function() {	
	var secret = "SECRET".toByteArray();
	var dt = Array.randomBytes(Math.floor(Math.random()* 20));
	return exports.mtCrypt(Date.now(), dt.concat(secret));
}


