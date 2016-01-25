var crypt = require("./crypt.js");
var fs = require("fs");

console.log("*** Challenge 1 ***")

var c1hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
console.log("Expected: SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
console.log("Result  : " + c1hex.hexDecode().base64Encode());
console.log("\n");

// -------

console.log("*** Challenge 2 ***")
var c2in = "1c0111001f010100061a024b53535009181c";
var c2key = "686974207468652062756c6c277320657965"
console.log("Expected: 746865206b696420646f6e277420706c6179");
console.log("Result  : " + c2in.hexDecode().xor(c2key.hexDecode()).hexEncode());
console.log("\n");

// -------

console.log("*** Challenge 3 ***")
var c3in = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
console.log("Result  : " + crypt.solveSingleCharacterXor(c3in.hexDecode()));
console.log("\n");

// -------

console.log("*** Challenge 4 ***")
var c4data = fs.readFileSync("4.txt").toString().split("\n");
with(crypt) {
	var max = -1;
	var result = "";
	c4data.forEach(function(e) {
		var r = solveSingleCharacterXor(e.hexDecode());
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
console.log(c5plain);
var c5key = "ICE";
console.log("Expected: 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
console.log("Result  : " + c5plain.toByteArray().xor(c5key.toByteArray()).hexEncode());
console.log("\n");

// -------

console.log("*** Challenge 6 ***")
with(crypt) {
	console.log("Hamm is " + hamm("this is a test".toByteArray(), "wokka wokka!!!".toByteArray()));
	var c6data = new Buffer(fs.readFileSync("6.txt").toString(),'base64').toString('hex').hexDecode();
	var dt = [];
	for (var i = 2; i <= 40; i++) {
		var a = hamm(c6data.slice(0, i), c6data.slice(i, 2*i)) / i;
		var b = hamm(c6data.slice(0, i), c6data.slice(2*i, 3*i)) / i;
		var c = hamm(c6data.slice(0, i), c6data.slice(3*i, 4*i)) / i;
		var d = hamm(c6data.slice(i, i*2), c6data.slice(2*i, 3*i)) / i;
		var e = hamm(c6data.slice(2*i, i*2), c6data.slice(3*i, 4*i)) / i;
		var score = Math.floor((a+b+c+d+e)/5.0 * 100);
		dt[score] = i;
	}
	dt = dt.filter(function(x) { return x != null }).slice(0,3);
	console.log("Best key lengths", dt);
	var max = -1;
	var result = "";
	console.log("Result: ")
	dt.forEach(function(klen){
		var blocks = [];
		for (var i = 0; i < c6data.length; i += klen) {
			blocks.push(c6data.slice(i, i + klen));
		}
		var key = [];
		for (var i = 0; i < klen; i++) {
			key.push(solveSingleCharacterXorWithKey(blocks.map(function(b) { return b[i]; })).key);
		}
		var r = c6data.xor(key).toAscii();
		var score = r.replace(/[^a-z]/ig, "").length;
		if (score > max) {
			result = r;
			max = score;
		}
	});
	console.log(result);
}

console.log("\n");

// -------


console.log("*** Challenge 7 ***")
with(crypt) {
	var c7data = fs.readFileSync("7.txt").toString();
	var result = aes256ecb_decrypt(c7data, "YELLOW SUBMARINE");
	console.log("Result: " + result.toAscii());
}
console.log("\n");

// -------


console.log("*** Challenge 8 ***")
var c8data = fs.readFileSync("8.txt").toString().split("\n");
var totalMax = -1;
var ecb = null;
c8data.forEach(function(ciphertext) {
	var counter = {};
	var dupCount = 0;
	for(var i = 0; i < ciphertext.length; i += 32) { //32 because each byte is 2 chars when hex encoded
		var block = ciphertext.slice(i, i + 32) 
		counter[block] = (counter[block] || 0) + 1;
		if (counter[block] > 1) {
			dupCount = dupCount + (counter[block] == 2 ? 2 : 1);
			console.log("Duplicate: " + block);
		}
	}
	if (dupCount > totalMax) {
		totalMax = dupCount;
		ecb = ciphertext;
	}
});
console.log("Repititions: " + totalMax);
console.log(ecb);





