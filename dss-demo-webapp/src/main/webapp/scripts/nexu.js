/**
 * 
 */

var nexuVersion = "1.3";

function nexu_get_certificates(success_callback, error_callback) {
	callUrl("http://localhost:9776/rest/certificates", "POST", {}, success_callback, error_callback);
}

/* function to use if we already know a certificate and its tokenId/keyId */
function nexu_sign_with_token_infos(tokenId, keyId, dataToSign, digestAlgo, success_callback, error_callback) {
	var data = '{ "tokenId":{"id":"' + tokenId + '"}, "keyId":"' + keyId + '", "toBeSigned": { "bytes": "' + dataToSign + '" } , "digestAlgorithm":"' + digestAlgo + '"}';
	callUrl("http://localhost:9776/rest/sign", "POST", data, success_callback, error_callback);
}

/* function to use without tokenId/keyId */
function nexu_sign(dataToSign, digestAlgo, success_callback, error_callback) {
	var data = { dataToSign:dataToSign, digestAlgo:digestAlgo };
	callUrl("http://localhost:9776/rest/sign", "POST", data, success_callback, error_callback);
}

function callUrl(url, type, data, success_callback, error_callback) {
	$.ajax({
		  type: type,
		  url: url,
		  data: data,
		  crossDomain: true, 
		  contentType: "application/json; charset=utf-8",
		  dataType: "json",
		  success: function (result) {
			  console.log(url + " : OK");
			  success_callback.call(this, result);
		  }
		}).fail(function (error, textStatus ) {
			console.log(url + " : KO " + textStatus);
			eval(error);
			error_callback.call(this, error);
		});
} 
