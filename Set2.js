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
	console.log(cbcDecrypt(c10data, "YELLOW SUBMARINE", [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]));

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
	var buf = new Buffer(c12len * 2);
	buf.fill('A');
	var c12_det = encryption_oracle_ecb(buf.toString()).hexEncode();
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
		//console.log('enc', crypt.asciiToNum(crypt.aes256ecb_encrypt(new Buffer(crypt.pkcs7pad(x, 16)), c13key)));
		return crypt.aes256ecb_encrypt(new Buffer(crypt.pkcs7pad(x, 16)), c13key).toByteArray();
	}
	function c13dec(data) {
		//console.log(data);
		var nums = crypt.aes256ecb_decrypt(data.base64Encode(), c13key)
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
}