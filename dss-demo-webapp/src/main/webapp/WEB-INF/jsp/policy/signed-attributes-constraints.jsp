<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#signed-attributes-block">
        <h3 class="panel-title">
            <spring:message code="label.policy.signedAttributes" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="signed-attributes-block">

        <spring:message code="label.policy.signingTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signingTime.level}" />
            <jsp:param name="pathToBind" value="MainSignature.MandatedSignedQProperties.SigningTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.contentType" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.contentType.level}" />
            <jsp:param name="pathToBind" value="MainSignature.MandatedSignedQProperties.ContentType.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signerLocation" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signerLocation.level}" />
            <jsp:param name="pathToBind" value="MainSignature.MandatedSignedQProperties.SignerLocation.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.claimedRoles" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.claimedRoles.level}" />
            <jsp:param name="pathToBind" value="MainSignature.MandatedSignedQProperties.ClaimedRoles.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.certifiedRoles" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.certifiedRoles.level}" />
            <jsp:param name="pathToBind" value="MainSignature.MandatedSignedQProperties.CertifiedRoles.Level" />
        </jsp:include>
        
        <c:set var="timestamp" value="${signedAttributes.contentTimeStamp}" scope="request" />
        <spring:message code="label.policy.content.timestamp" var="title" />
        <jsp:include page="timestamp-constraints.jsp">
            <jsp:param name="id" value="content-timestamp" />
            <jsp:param name="title" value="${title}" />
            <jsp:param name="pathToBindPrefix" value="MainSignature.MandatedSignedQProperties.ContentTimeStamp" />
        </jsp:include>

    </div>
</div>
<c:remove var="signedAttributes" />