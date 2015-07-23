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
	function addCertificate(base64Certificate, readableCertificate) {
	    $('#certificate').append('<input type="radio" name="base64Certificate" value="'+base64Certificate+'" /> '+readableCertificate+'<br />');
	}
</script>

<jsp:include page="applet-warning.jsp" />