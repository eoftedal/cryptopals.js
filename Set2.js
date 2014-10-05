var crypt = require("./crypt.js");
var fs = require("fs");

with(crypt) {
	console.log("*** Challenge 9 ***")
	var a = asciiToNum("YELLOW SUBMARINE")
	a.push(4); a.push(4); a.push(4); a.push(4);
	console.log("Expected: " + a);
	console.log("Result  : " + pkcs7pad(asciiToNum("YELLOW SUBMARINE"), 20));










}