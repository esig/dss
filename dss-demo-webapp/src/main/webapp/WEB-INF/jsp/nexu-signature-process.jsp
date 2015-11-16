<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>NexU signature process</h2>
     
<div class="progress">
	<div class="progress-bar progress-bar-striped active" style="width:0%" id="bar">
		<span id="bar-text"></span>
		</div>
</div>
<div id="error" style="display:none" class="alert alert-danger" role="danger"><strong id="errorText">Oops... an error occurred </strong><span id="errorcontent"></span></div>

<%-- <script src="${pageContext.request.contextPath}/js/nexu-deploy.js" type="text/javascript"></script> --%>

<script src="scripts/nexu.js" type="text/javascript"></script>

<script type="text/javascript" defer>

	var tokenId;
	var keyId;
	
	window.onload = function() {
		getCertificates();
	};
	
	function getCertificates() {
		updateProgressBar("Loading certificates...", "10%");
	    nexu_get_certificates(getDataToSign, error);
	}
	
	function getDataToSign(certificateData) {
		if(certificateData.response == null) {
			$('#bar').removeClass('progress-bar-success active').addClass('progress-bar-danger');
			$('#bar-text').html("Error");
			document.getElementById("errorcontent").innerHTML = "error while reading the Smart Card";
			$("#error").show();
		} else {
			updateProgressBar("Computing the digest...", "25%");
		    var signingCertificate = certificateData.response.certificate;
		    var certificateChain = certificateData.response.certificateChain;
		    var encryptionAlgorithm = certificateData.response.encryptionAlgorithm;
		    tokenId = certificateData.response.tokenId.id;
		    keyId = certificateData.response.keyId;
		    var toSend = { signingCertificate: signingCertificate, certificateChain: certificateChain, encryptionAlgorithm: encryptionAlgorithm };
		    callUrl("nexu/get-data-to-sign", "POST",  JSON.stringify(toSend) , sign, error);
		}
	}
	
	function sign(dataToSignResponse) {
		updateProgressBar("Signing the digest...", "50%");
		var digestAlgo = "${signatureDocumentForm.digestAlgorithm.name}";
		nexu_sign_with_token_infos(tokenId, keyId, dataToSignResponse.dataToSign, digestAlgo, signDocument, error);
	}
	
	function signDocument(signatureData) {
		updateProgressBar("Signing the document...", "75%");
		var signatureValue = signatureData.response.signatureValue;
		var toSend = {signatureValue:signatureValue};
	    callUrl("nexu/sign-document", "POST", JSON.stringify(toSend), downloadSignedDocument, error);
	}
	
	function downloadSignedDocument(signDocumentResponse) {
		var url = signDocumentResponse.urlToDownload;
		url = "nexu/download";
		window.open(url, "_self");
		updateProgressBar("Done !", "100%");
		$('#bar').removeClass('progress-bar-striped active');
		$('#bar').addClass('progress-bar-success');
	}
	
	function error(error) {
		$('#bar').removeClass('progress-bar-success active').addClass('progress-bar-danger');
		$("#errorcontent").html(error.responseText);
	    $("#error").show();
	    $("#success").hide();
	}
	
	function updateProgressBar(action, percent) {
		$('#bar-text').html(action);
		$('#bar').width(percent);
	}
	
</script> 