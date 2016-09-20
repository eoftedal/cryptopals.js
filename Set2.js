var crypt = require("./crypt.js");
var fs = require("fs");

with(crypt) {

	console.log("*** Challenge 9 ***")
	var a = "YELLOW SUBMARINE".toByteArray();
	a.push(4); a.push(4); a.push(4); a.push(4);
	console.log("Expected: " + a.hexEncode());
	console.log("Result  : " + pkcs7pad("YELLOW SUBMARINE".toByteArray(), 20).hexEncode());

// ----
	console.log("\n")
	console.log("*** Challenge 10 ***");
	var c10data = fs.readFileSync("10.txt").toString();
	var c10plain = cbcDecrypt(c10data.base64Decode(), "YELLOW SUBMARINE", [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0])
	var c10ciph = cbcEncrypt(c10plain.toByteArray(), "YELLOW SUBMARINE", [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]);
	var c10a = c10data.base64Decode().hexEncode();
	var c10b = c10ciph.base64Decode().hexEncode();
	console.log("SAME RESULT: " + (c10a == c10b));

// ----
	console.log("\n")
	console.log("*** Challenge 11 ***");
	for (var i = 0; i < 10; i++) {
		var cipher = encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toByteArray());
		if (cipher.slice(16, 32).base64Encode() == cipher.slice(32, 48).base64Encode()) {
			console.log("Detected: ECB");
		} else {
			console.log("Detected: CBC")
		}
	}

// ----
	console.log("\n")
	console.log("*** Challenge 12 ***");
	var c12len = detect_key_length();
	console.log("Detected key length: " + c12len);
	var data = Array.of(c12len * 2, 'A');
	var c12_det = encryption_oracle_ecb(data.join('')).hexEncode();
	console.log("Is CBC? " + (c12_det.substring(0, c12len*2) == c12_det.substring(c12len*2, c12len * 4)));
	oracle_decrypt(c12len);

// ----

	console.log("\n")
	console.log("*** Challenge 13 ***");
	var c13 = "foo=bar&baz=qux&zap=zazzle";
	var c13obj = parseParameters(c13);
	console.log(JSON.stringify(c13obj));
	profile_for('foo@bar.com');
	console.log(profile_for('foo@bar.com'));
	var c13key = generateKey(16);
	function c13enc(email) {
		var x = crypt.profile_for(email).toByteArray();
		return crypt.aes256ecb_encrypt(crypt.pkcs7pad(x, 16), c13key).hexDecode();
	}
	function c13dec(data) {
		//console.log(data);
		var nums = crypt.aes256ecb_decrypt(data, c13key)
		nums = nums.slice(0, nums.length - nums[nums.length - 1]);
		return crypt.parseParameters(nums.toAscii());
	}
	console.log(JSON.stringify(c13dec(c13enc('hey@ho'))));
	var c13x = "aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
	var c13y = "aaaaaa@bbbbbb";
	var c13block = c13enc(c13x).slice(16,32);	
	var c13m = c13enc(c13y);
	c13m = c13m.slice(0, c13m.length - 16);
	console.log(JSON.stringify( c13dec(c13m.concat(c13block)) ));

// ----

	console.log("\n")
	console.log("*** Challenge 14 ***");

	var x = Array.randomBytes(1)[0] % 20;
	var prefix = Array.randomBytes(x);
	var key = generateKey(16);
	var plain = "secret".toByteArray();
	var prev = "";
	function enc_p(m) {
		var d = crypt.pkcs7pad(prefix.concat(m).concat(plain), 16);
		return crypt.aes256ecb_encrypt(d, key);
	}
	for (var i = 0; i < 48; i++) {
		var h = enc_p(Array.of(i, 0x65));
		if (h.length >= 32 && prev == h.substring(0,64)) {
			break;
		}
		prev = h.substring(0,64);
	}
	i -= 2;
	var target = enc_p(Array.of(i, 0x65));
	var t_l = target.length;
	var result = [];
	do {
		var t = target.substring(0,64);
		for (var j = 0; j < 256; j++) {
			var t_p = enc_p(Array.of(i, 0x65).concat(result).concat(j));
			if (t_p.substring(0, 64) == target.substring(0, 64)) {
				result.push(j);
				break;
			}
		}
		i--;
		target = enc_p(Array.of(i, 0x65));
		console.log(i, result.toAscii());
		
	} while(target.length == t_l);
	console.log("PLAIN : " + plain.toAscii());
	console.log("RESULT: " + result.toAscii());

//---

	console.log("\n")
	console.log("*** Challenge 15 ***");
	var c15_key = generateKey(16);
	var c15_iv = Array.prototype.slice.apply(generateKey(16));
	function c15_encrypt(data) {
		for (var i = 0; i < data.length; i++) {
			if (data[i] == ";".toByte() || data[i] == "=".toByte()){
				data[i] = "_".toByte();
			}
		}
		var dt = "comment1=cooking%20MCs;userdata=".toByteArray().concat(data).concat(";comment2=%20like%20a%20pound%20of%20bacon".toByteArray());
		return crypt.cbcEncrypt(crypt.pkcs7pad(dt, 16), c15_key, c15_iv).base64Decode();
	}
	function c15_check(cipher) {
		var k = crypt.cbcDecrypt(cipher, c15_key, c15_iv);
		return k.indexOf(";admin=true;") > -1;
	}
	var c15res = c15_encrypt("0123456789abcdef;admin=true".toByteArray());
	console.log("HAS ;admin=true; BEFORE FLIPS: ", c15_check(c15res));
	c15res[32] ^= "_".toByte() ^ ";".toByte();
	c15res[38] ^= "_".toByte() ^ "=".toByte();
	console.log("HAS ;admin=true; AFTER FLIPS : ", c15_check(c15res));

//---
	console.log("\n")
	console.log("*** Challenge 16 ***");
	function c16_f(s, t) {
		console.log("paddingValid - expected: " + t + " - was: " + crypt.paddingValid(s));
	}
	c16_f("ICE ICE BABY\x04\x04\x04\x04", true);
	c16_f("ICE ICE BABY\x05\x05\x05\x05", false);
	c16_f("ICE ICE BABY\x01\x02\x03\x04", false);
}







