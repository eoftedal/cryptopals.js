
exports.hexToNum = function(data) {
	var result = [];
	for(var i = 0; i < data.length; i += 2) {
		result.push(parseInt(data[i] + data[i + 1], 16));
	}
	return result;
}

exports.numToBase64 = function(data) {
	return new Buffer(data).toString('base64');
}
