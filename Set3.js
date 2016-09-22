var crypt = require("./crypt.js");
var fs = require("fs");

with(crypt) {
	(function() {
		console.log("\n*** Challenge 17 ***");
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
			var str = strings[ix].base64Decode().toAscii();
			console.log("Expected: " + str);
			var data = str.toByteArray();
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
		console.log("\n*** Challenge 18 ***");
		var key = "YELLOW SUBMARINE".toByteArray();
		var cipher = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".base64Decode();
		var out = aesctr(key, Array.of(8, 0), cipher);
		console.log(out.toAscii());
	})();

	(function() {
		console.log("\n*** Challenge 19 ***");
		var dt = [
			"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
			"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
			"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
			"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
			"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
			"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
			"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
			"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
			"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
			"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
			"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
			"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
			"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
			"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
			"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
			"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
			"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
			"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
			"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
			"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
			"U2hlIHJvZGUgdG8gaGFycmllcnM/",
			"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
			"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
			"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
			"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
			"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
			"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
			"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
			"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
			"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
			"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
			"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
			"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
			"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
			"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
			"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
			"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
			"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
		];
		var key = Array.randomBytes(16);
		console.log(dt.map(x=>x.base64Decode().toAscii()).join("\n"));
		var ciphers = dt.map(x => x.base64Decode()).map(x => aesctr(key, Array.of(8, 0), x));
		var max = ciphers.map(x=>x.length).sort().reverse()[0];
		console.log(max);
		var k = [];
		for(var i = 0; i < max; i++) {
			var chars = ciphers.filter(x => x[i] != null).map(x => x[i]);
			k[i] = [];
			for(var j = 0; j < 256; j++) {
				var x = chars.map(x=>x^j).filter(x => String.fromCharCode(x).match(/[a-zA-Z.' ,:;\-?]/)).length;
				if (x == chars.length) k[i].push(j);
			}
		}
		var possible = ciphers.map(x => 
			x.map((y,i) => {
				var p = k[i];
				return p.map(l => l ^ y);
			})
		);
		console.log(possible.map(x => x.map(y => y.length == 1 ? y.toAscii() : "[" + y.toAscii() + "]").join("")).join("\n"));
		console.log("---- Improved manually -----------------------");
		function pick(ix, c) { //Pick letter c on longest line 37 for letter number ix
			var i = possible[37][ix].indexOf(c.toByte());
			possible.forEach(x => {
				if (x[ix] != null) x[ix] = [x[ix][i]];
			});	
		}
		pick(0, "H");
		pick(1, "e");
		pick(3, " ");
		pick(14, "e");
		pick(26, "i");
		pick(30, "i");
		pick(31, "s");
		pick(32, " ");
		pick(33, "t");
		pick(34, "u");
		pick(35, "r");
		pick(36, "n");
		pick(37, ",");
		console.log(possible.map((x,i) => x.map(y => y.length == 1 ? y.toAscii() : "[" + y.toAscii() + "]").join("")).join("\n"));
	})();


	(function() {
		console.log("\n*** Challenge 20 ***");
		var dt = fs.readFileSync("20.txt", "utf-8").split(/\n/g).filter(x => x != "").map(x => x.base64Decode());
		var min = 1000;
		dt.forEach(x => {
			if (x.length < min) min = x.length;			
		});
		console.log(min);
		var key = Array.randomBytes(16);
		var ciphers = dt.map(x => x.slice(0, min)).map(x => aesctr(key, Array.of(8, 0), x));

		var key = [];
		for (var i = 0; i < min; i++) {
			key.push(solveSingleCharacterXorWithKey(ciphers.map(b => b[i])).key);
		}
		console.log(ciphers.map(x => x.xor(key).toAscii()).join("\n"));
	})();















}