var crypt = require("./crypt.js");

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
var c2in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
with(crypt) {
console.log("Result  : " + solveSingleCharacterXor(hexToNum(c2in)));
}

