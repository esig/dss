<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#block-${param.id}">
        <h3 class="panel-title">
            ${param.title}
        </h3>
    </div>
    <div class="panel-body collapse in" id="block-${param.id}">

        <c:if test="${param.id != 'countersignature'}">
            <spring:message code="label.policy.structuralValidation" var="translation" />
            <jsp:include page="level-constraint.jsp">
                <jsp:param name="label" value="${translation}" />
                <jsp:param name="levelValue" value="${signature.structuralValidation.level}" />
                <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.StructuralValidation.Level" />
            </jsp:include>
            
            <c:set var="multiValuesConstraint" value="${signature.acceptablePolicies}" scope="request" />
            <spring:message code="label.policy.acceptablePolicies" var="translation" />
            <jsp:include page="multi-values-constraint.jsp">
                <jsp:param name="label" value="${translation}" />
                <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.acceptablePolicies" />
            </jsp:include>
        </c:if>
        
        <spring:message code="label.policy.referenceDataExistence" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataExistence.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.ReferenceDataExistence.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataIntact.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.ReferenceDataIntact.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signatureIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.signatureIntact.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.SignatureIntact.Level" />
        </jsp:include>
        
        <c:if test="${param.id != 'countersignature'}">
            <c:set var="currentCertificate" value="${signature.signingCertificate}" scope="request" />
            <spring:message code="label.policy.signingCertificate" var="translation" />
            <jsp:include page="certificate-constraints.jsp">
                <jsp:param name="id" value="signing-cert-signature" />
                <jsp:param name="title" value="${translation}" />
                <jsp:param name="pathToBindPrefix" value="${param.pathToBindPrefix}.SigningCertificate" />
            </jsp:include>
            
            <c:set var="currentCertificate" value="${signature.CACertificate}" scope="request" />
            <spring:message code="label.policy.caCertificate" var="translation" />
            <jsp:include page="certificate-constraints.jsp">
                <jsp:param name="id" value="ca-cert-signature" />
                <jsp:param name="title" value="${translation}" />
                <jsp:param name="pathToBindPrefix" value="${param.pathToBindPrefix}.CACertificate" />
            </jsp:include>
            
            <c:set var="signedAttributes" value="${signature.mandatedSignedQProperties}" scope="request" />
            <jsp:include page="signed-attributes-constraints.jsp" />
            
            <c:set var="unsignedAttributes" value="${signature.mandatedUnsignedQProperties}" scope="request" />
            <jsp:include page="unsigned-attributes-constraints.jsp" />
            
<%--             <c:set var="cryptographic" value="${signature.cryptographic}" scope="request" /> --%>
<%--             <jsp:include page="cryptographic-constraints.jsp" /> --%>
        </c:if>
    </div>
</div>
<c:remove var="signature" />