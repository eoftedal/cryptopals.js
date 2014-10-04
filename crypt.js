
exports.hexToNum = function(data) {
	var result = [];
	for(var i = 0; i < data.length; i += 2) {
		result.push(parseInt(data[i] + data[i + 1], 16));
	}
	return result;
}

exports.numToHex = function(data) {
	return data.map(function(x) { return (x < 16 ? '0' : '') + x.toString(16); }).join("");
}

exports.numToBase64 = function(data) {
	return new Buffer(data).toString('base64');
}

exports.xor = function(num1, num2) {
	return num1.map(function(x, i) { return x ^ num2[i % num2.length]; });
}

exports.numToAscii = function(data) {
	return String.fromCharCode.apply(this, data);
}
exports.asciiToNum = function(data) {
	var result = [];
	for (var i in data) { result.push(data.charCodeAt(i)); }
	return result;
}

exports.numOfAscii = function(data) {
	return data.split(/[a-zA-Z ]/).length
}

exports.solveSingleCharacterXor = function(data) {
	var max = -1;
	var selected = -1;
	for(var i = 0; i < 256; i++) {
		var res = exports.numOfAscii(exports.numToAscii(exports.xor(data, [i])));
		if (res > max) {
			selected = i;
			max = res;
		}
	}
	return exports.numToAscii(exports.xor(data, [selected]));
}