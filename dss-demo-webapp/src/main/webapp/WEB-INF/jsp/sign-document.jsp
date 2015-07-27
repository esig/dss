<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.signADocument"/></h2>

<c:set var="backslash">\</c:set>
<c:set var="backslashReplace">\\</c:set>

<script src="//www.java.com/js/deployJava.js"></script>
<script type="text/javascript">
    var attributes = {
        width: 1,
        height: 1
    };
    var parameters = {
        operation : 'sign_digest',
        token : '<c:out value="${signatureDocumentForm.token}"/>',
        pkcs11LibPath : '<c:out value="${fn:replace(signatureDocumentForm.pkcsPath, backslash, backslashReplace)}" />',
        pkcs11Pwd : '<c:out value="${signatureDocumentForm.pkcsPassword}"/>',
        base64Digest : '<c:out value="${digest}"/>',
        digestAlgo : '<c:out value="${signatureDocumentForm.digestAlgorithm}"/>',
        base64Certificate : '<c:out value="${signatureDocumentForm.base64Certificate}"/>',
        jnlp_href: 'jnlp/light-applet.jnlp'
    };
    var version = '1.6';
    deployJava.runApplet(attributes, parameters, version);
</script>

<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">
    <div class="hidden" id="signature-fields">
        <input type="hidden" name="sign-document" value="" />
    </div>
</form:form>

<script type="text/javascript">
    function addSignature(base64SignatureValue) {
        $('#signature-fields')
    		.append('<input type="hidden" name="base64SignatureValue" value="'+base64SignatureValue+'" />');
        
        $('#signatureDocumentForm').submit();
    }
</script>