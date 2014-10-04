var crypt = require("./crypt.js");
var fs = require("fs");

console.log("*** Challenge 1 ***")

var c1hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
console.log("Expected: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
console.log("Result  : " + crypt.numToBase64(crypt.hexToNum(c1hex)));
console.log("\n");

// -------

console.log("*** Challenge 2 ***")
var c2in = "1c0111001f010100061a024b53535009181c";
var c2key = "686974207468652062756c6c277320657965"
console.log("Expected: 746865206b696420646f6e277420706c6179");
with(crypt) {
console.log("Result  : " + numToHex(xor(hexToNum(c2in), hexToNum(c2key))));
}
console.log("\n");

// -------

console.log("*** Challenge 3 ***")
var c3in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
with(crypt) {
console.log("Result  : " + solveSingleCharacterXor(hexToNum(c3in)));
}
console.log("\n");

// -------

console.log("*** Challenge 4 ***")
var c4data = fs.readFileSync("4.txt").toString().split("\n");
with(crypt) {
	var max = -1;
	var result = "";
	c4data.forEach(function(e) {
		var r = solveSingleCharacterXor(hexToNum(e));
		var n = numOfAscii(r);
		if (n > max) {
			max = n;
			result = r;
		}
	});
	console.log("Result  : " + result);
}
console.log("\n");

// -------

console.log("*** Challenge 5 ***")
var c5plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
var c5key = "ICE";
with(crypt) {
console.log("Expected: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
console.log("Result  : " + [c5plain].map(asciiToNum).map(function(x) { return xor(x, asciiToNum(c5key)) }).map(numToHex).join("\n")  );
}
console.log("\n");






