<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.signADocument"/></h2>

<script src="//www.java.com/js/deployJava.js"></script>
<script type="text/javascript">
    var attributes = {
        width: 1,
        height: 1
    };
    var parameters = {
        operation : 'load_certificates',
        token : '<c:out value="${signatureDocumentForm.token}"/>',
        jnlp_href: 'jnlp/light-applet.jnlp'
    };
    var version = '1.6';
    deployJava.runApplet(attributes, parameters, version);
</script>

<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">

    <div class="form-group">
        <form:label path="base64Certificate" cssClass="col-sm-2 control-label">
            <spring:message code="label.select.certificate" />
        </form:label>
        <div class="col-sm-10" id="certificate"></div>
        <div class="col-sm-10" id="certificateChain"></div>
        <div class="col-sm-10" id="encryptionAlgo"></div>
    </div>

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary" name="data-to-sign">
                <spring:message code="label.submit" />
            </button>
        </div>
    </div>

</form:form>

<script type="text/javascript">
    var mapCertificateChain = new Object();
    var mapEncryptionAlgo = new Object();

	function addCertificate(base64Certificate, readableCertificate, encryptionAlgo) {
        $('#certificate').append('<input type="radio" name="base64Certificate" value="'+base64Certificate+'" /> ' + readableCertificate + '<br />');
        mapEncryptionAlgo[base64Certificate] = encryptionAlgo;
	}

	function addCertificateChain(base64Certificate, chainElement) {
	    var tab = mapCertificateChain[base64Certificate];
	    if (tab == null){
	        tab = [];
	        mapCertificateChain[base64Certificate] = tab;
	    }
	    tab[tab.length] = chainElement;

	    console.log("addCertChain : "+ base64Certificate +" "+ chainElement);
	    console.log("end addCertChain : "+tab);
	}
       

    $("#certificate").on("change", "input[type=radio]", function() {
        $("#certificateChain").empty();
        $("#encryptionAlgo").empty();
        var chain = mapCertificateChain[$(this).val()];
        var algo = mapEncryptionAlgo[$(this).val()];

        console.log("checked " + chain);
        if (chain != null) {
            for (var i = 0; i < chain.length; i++) {
                console.log("add hidden chain " + chain[i]);
                $("#certificateChain").append('<input type="hidden" name="base64CertificateChain['+i+']" value="'+chain[i]+'" />');
            }
        }
        
        if (algo != null) {
            $("#encryptionAlgo").append('<input type="hidden" name="encryptionAlgorithm" value="'+algo+'" />');
        }
    });
</script>

<jsp:include page="applet-warning.jsp" />