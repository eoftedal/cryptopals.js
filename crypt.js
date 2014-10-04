
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
	return num1.map(function(x, i) { return x ^ num2[i]; });
}