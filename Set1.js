var crypt = require("./crypt.js");

console.log("*** Challenge 1 ***")

var c1hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
console.log("Expected: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")
console.log("Result  : " + crypt.numToBase64(crypt.hexToNum(c1hex)));
console.log("\n\n");

