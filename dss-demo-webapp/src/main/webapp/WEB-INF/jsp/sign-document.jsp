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
        operation : 'sign_digest',
        token : '<c:out value="${signatureDocumentForm.token}"/>',
        base64Digest : '<c:out value="${digest}"/>',
        digestAlgo : '<c:out value="${signatureDocumentForm.digestAlgorithm}"/>',
        base64Certificate : '<c:out value="${signatureDocumentForm.base64Certificate}"/>',
        jnlp_href: 'jnlp/light-applet.jnlp'
    };
    var version = '1.6';
    deployJava.runApplet(attributes, parameters, version);
</script>
