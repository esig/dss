<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>NexU</h2>
<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">

    <input type="hidden" id="isSign" value="true" />

    <div class="form-group">
        <form:label path="documentToSign" cssClass="col-sm-2 control-label">
            <spring:message code="label.to.sign.file" />
        </form:label>
        <div class="col-sm-4">
            <form:input path="documentToSign" type="file" />
        </div>
        <div class="col-xs-4 col-md-offset-2">
            <form:errors path="documentToSign" cssClass="text-danger" />
        </div>
    </div>

    <jsp:include page="fields/signatureForm.jsp" />
    
    <jsp:include page="fields/signaturePackaging.jsp" />
    
    <jsp:include page="fields/signatureLevel.jsp" />

    <div class="form-group">
        <form:label path="digestAlgorithm" cssClass="col-sm-2 control-label">
            <spring:message code="label.digest.algorithm" />
        </form:label>
        <div class="col-sm-6">
            <c:forEach var="algo" items="${digestAlgos}">
                <label class="radio-inline"> <form:radiobutton path="digestAlgorithm" value="${algo}" /> ${algo}</label>
            </c:forEach>
        </div>
        <div class="col-xs-4">
            <form:errors path="digestAlgorithm" cssClass="text-danger" />
        </div>
    </div>
    
    <div class="form-group">
        <form:label path="documentToSign" cssClass="col-sm-2 control-label">
            <spring:message code="label.allow.expired.certificate" />
        </form:label>
        <div class="col-sm-4">
            <form:checkbox path="signWithExpiredCertificate" />
        </div>
    </div>

<!-- 	<div id="nexu"></div> -->
<%--    	<c:if test="${fields.hasErrors('nexuDetected')}"> --%>
<!--     	<div class="form-group"> -->
<!--     		<div class="col-sm-offset-2 col-sm-10 text-danger"> -->
<%--     			<form:errors path="*{nexuDetected}" cssClass="error"/> --%>
<!--     		</div> -->
<!-- 	    </div> -->
<%--    	</c:if> --%>

    <div class="panel panel-default">
        <div class="panel-heading" data-toggle="collapse" data-target="#block-policy">
            <spring:message code="label.policy" />
        </div>
        <div class="panel-body collapse in" id="block-policy">
            <div class="form-group">
                <form:label path="policyOid" cssClass="col-sm-3 control-label">
                    <spring:message code="label.policy.oid" />
                </form:label>
                <div class="col-sm-4">
                    <form:input path="policyOid" size="50" />
                </div>
            </div>
            <div class="form-group">
                <form:label path="policyDigestAlgorithm" cssClass="col-sm-3 control-label">
                    <spring:message code="label.digest.algorithm" />
                </form:label>
                <div class="col-sm-8">
                    <c:forEach var="algo" items="${digestAlgos}">
                        <label class="radio-inline"> <form:radiobutton path="policyDigestAlgorithm" value="${algo}" /> ${algo}</label>
                    </c:forEach>
                </div>
            </div>
            <div class="form-group">
                <form:label path="policyBase64HashValue" cssClass="col-sm-3 control-label">
                    <spring:message code="label.policy.hash.value" />
                </form:label>
                <div class="col-sm-4">
                    <form:input path="policyBase64HashValue" size="50" />
                </div>
            </div>
        </div>
    </div>

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary" id="submit-button"><spring:message code="label.submit"/></button>
            <button type="reset" class="btn"><spring:message code="label.clear"/></button>
        </div>
    </div>   
</form:form>

<script type="text/javascript" src="<c:url value="/scripts/jsSignatureLevel.js" />"></script>

<script type="text/javascript" src="<c:url value="/js/nexu-deploy.js" />"></script>