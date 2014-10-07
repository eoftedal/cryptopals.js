var crypt = require("./crypt.js");
var fs = require("fs");

with(crypt) {
	console.log("*** Challenge 9 ***")
	var a = asciiToNum("YELLOW SUBMARINE")
	a.push(4); a.push(4); a.push(4); a.push(4);
	console.log("Expected: " + a);
	console.log("Result  : " + pkcs7pad(asciiToNum("YELLOW SUBMARINE"), 20));

// ----
	console.log("\n")
	console.log("*** Challenge 10 ***");
	var c10data = fs.readFileSync("10.txt").toString();
	console.log(cbcDecrypt(c10data, "YELLOW SUBMARINE", [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0]));

// ----
	console.log("\n")
	console.log("*** Challenge 11 ***");
	for (var i = 0; i < 10; i++) {
		var cipher = encryption_oracle(asciiToNum("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
		if (numToBase64(cipher.slice(16, 32)) == numToBase64(cipher.slice(32, 48))) {
			console.log("Detected: ECB");
		} else {
			console.log("Detected: CBC")
		}
	}




}