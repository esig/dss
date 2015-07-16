<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.signADocument"/></h2>
<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">

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

    <div class="form-group">
        <form:label path="digestAlgorithm" cssClass="col-sm-2 control-label">
            <spring:message code="label.digest.algorithm" />
        </form:label>
        <div class="col-sm-6">
            <c:forEach var="algo" items="${digestAlgos}" varStatus="loop">
                <label class="radio-inline"> <form:radiobutton path="digestAlgorithm" value="${algo}" /> ${algo}</label>
                <c:if test="${((loop.index+1) % 4) == 0}"><br /></c:if>
            </c:forEach>
        </div>
        <div class="col-xs-4">
            <form:errors path="digestAlgorithm" cssClass="text-danger" />
        </div>
    </div>

    <div class="form-group">
        <form:label path="token" cssClass="col-sm-2 control-label">
            <spring:message code="label.tokenType" />
        </form:label>
        <div class="col-sm-6">
            <c:forEach var="tokenType" items="${tokenTypes}">
                <label class="radio-inline"> <form:radiobutton path="token" value="${tokenType}" /> <spring:message code="label.${tokenType}" />
                </label>
            </c:forEach>
        </div>
        <div class="col-xs-4">
            <form:errors path="token" cssClass="text-danger" />
        </div>
    </div>
    
    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary"><spring:message code="label.submit"/></button>
            <button type="reset" class="btn"><spring:message code="label.clear"/></button>
        </div>
    </div>   

</form:form>