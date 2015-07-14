<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#signature-block">
        <h3 class="panel-title">
            <spring:message code="label.policy.title.signature" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="signature-block">

        <spring:message code="label.policy.structuralValidation" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.structuralValidation.level}" />
            <jsp:param name="pathToBind" value="MainSignature.StructuralValidation.Level" />
        </jsp:include>
        
        <c:set var="multiValuesConstraint" value="${signature.acceptablePolicies}" scope="request" />
        <spring:message code="label.policy.acceptablePolicies" var="translation" />
        <jsp:include page="multi-values-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param value="pathToBind" name="mainSignature.acceptablePolicies" />
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataExistence" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataExistence.level}" />
            <jsp:param name="pathToBind" value="MainSignature.ReferenceDataExistence.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataIntact.level}" />
            <jsp:param name="pathToBind" value="MainSignature.ReferenceDataIntact.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signatureIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.signatureIntact.level}" />
            <jsp:param name="pathToBind" value="MainSignature.SignatureIntact.Level" />
        </jsp:include>
        
        <c:set var="currentCertificate" value="${signature.signingCertificate}" scope="request" />
        <spring:message code="label.policy.signingCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="MainSignature.SigningCertificate" />
        </jsp:include>
        
        <c:set var="currentCertificate" value="${signature.CACertificate}" scope="request" />
        <spring:message code="label.policy.caCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="MainSignature.CACertificate" />
        </jsp:include>
        
        
    </div>
</div>
<c:remove var="signature" />