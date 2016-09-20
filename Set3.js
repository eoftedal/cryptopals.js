var crypt = require("./crypt.js");
var fs = require("fs");

with(crypt) {
	(function() {
		console.log("*** Challenge 17 ***");
		var key = Array.randomBytes(16);
		function getCipher() {
			var strings = [
				"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
				"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
				"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
				"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
				"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
				"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
				"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
				"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
				"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
				"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
			];
			var ix = Math.floor(Math.random()*10);
			console.log("Expected: " + strings[ix]);
			var data = strings[ix].toByteArray();
			var iv = Array.randomBytes(16);
			var cipher = padAndCbcEncrypt(data, key, iv);
			return iv.concat(cipher.base64Decode());
		}
		var cipherAndIv = getCipher();
		var cipher = cipherAndIv.slice(16)
		var num = cipher.length/16;
		var result = [];
		for (var b = 0; b < num; b++) { //Go block by block
			var rndIv = Array.randomBytes(16);
			var iv = cipherAndIv.slice(b*16, (b+1)*16);
			for (var i = 1; i <= 16; i++) { //Go byte by byte starting from last
				for (var g = 0; g < 256; g++) { //Test all values for byte
					try {
						rndIv[16 - i] = g;
						cbcDecryptAndRemovePadding(cipher.slice(b*16, (b+1)*16), key, rndIv);
						var riv = rndIv.slice();
						if (i == 1) { //Make sure we found the right padding for last byte and not 0x02 or larger
							riv[16-i-1] = riv[16-i-1] ^ 0xff; 
							cbcDecryptAndRemovePadding(cipher.slice(b*16, (b+1)*16), key, riv);
						}
						break; //We found the correct padding
					} catch(e) { 
						//We failed to find the right padding and have to try the next one 
					}
				}
				if (g == 256) process.exit(1);
				if (i < 16) {
					for (var j = 1; j <= i; j++) {
						rndIv[16-j] = rndIv[16-j] ^ i ^ (i+1); //Increment the padding count for the known bytes
					} 
				} else {
					result = result.concat(rndIv.map((x,n) => iv[n] ^ 16 ^ x)); //Find plain by xoring with previous block
				}
			}
		}
		var pad = result[result.length -1];
		for(var i = 0; i < pad; i++) result.pop();
		console.log("Actual  : " + result.toAscii());
	})();

	(function() { 
		console.log("*** Challenge 18 ***");
		var key = "YELLOW SUBMARINE".toByteArray();
		var cipher = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".base64Decode();
		var out = aesctr(key, Array.of(8, 0), cipher);
		console.log(out.toAscii());
	})();



}