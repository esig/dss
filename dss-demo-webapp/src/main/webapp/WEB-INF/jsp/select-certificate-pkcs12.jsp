<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.signADocument"/></h2>

<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">

    <div class="form-group">
        <form:label path="base64Certificate" cssClass="col-sm-2 control-label">
            <spring:message code="label.select.certificate" />
        </form:label>
        <div class="col-sm-10" id="certificate">
            <c:forEach var="key" items="${keys}">
                <c:set var="tootltip" value="" />
                <c:if test="${not empty key.certificate.keyUsageBits}">
                    <c:set var="tooltip">Key usage(s) : ${key.certificate.keyUsageBits}</c:set>
                </c:if>
                <input type="radio" name="base64Certificate" value="${key.certificate.base64Encoded}" /> <span data-toggle="tooltip" data-placement="right" title="${tooltip}"> ${key.certificate.readableCertificate}</span><br />
            </c:forEach>
        </div>
    </div>

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary" name="sign-document-pkcs12">
                <spring:message code="label.submit" />
            </button>
        </div>
    </div>

</form:form>

<script type="text/javascript">
	$('[data-toggle="tooltip"]').tooltip();
</script>
