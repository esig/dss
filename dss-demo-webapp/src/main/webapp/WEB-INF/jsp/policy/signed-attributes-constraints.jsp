<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#signed-attributes-block-<c:out value="${param.id}"/>">
        <h3 class="panel-title">
            <spring:message code="label.policy.signedAttributes" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="signed-attributes-block-<c:out value="${param.id}"/>" >

		<spring:message code="label.policy.signingCertificatePresent" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signingCertificatePresent.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.SigningCertificatePresent.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signingCertificateSigned" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signingCertificateSigned.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.SigningCertificateSigned.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.digestValuePresent" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.certDigestPresent.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.CertDigestPresent.Level" />
        </jsp:include>

        <spring:message code="label.policy.digestValueMatch" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.certDigestMatch.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.CertDigestMatch.Level" />
        </jsp:include>

        <spring:message code="label.policy.issuerSerialMatch" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.issuerSerialMatch.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.IssuerSerialMatch.Level" />
        </jsp:include>
		
        <spring:message code="label.policy.signingTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signingTime.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.SigningTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.contentType" var="translation" />
        <jsp:include page="value-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.contentType.level}" />
            <jsp:param name="value" value="${signedAttributes.contentType.value}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.ContentType" />
        </jsp:include>
        
        <spring:message code="label.policy.contentHints" var="translation" />
        <jsp:include page="value-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.contentHints.level}" />
            <jsp:param name="value" value="${signedAttributes.contentHints.value}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.ContentHints" />
        </jsp:include>
        
        <spring:message code="label.policy.contentIdentifier" var="translation" />
        <jsp:include page="value-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.contentIdentifier.level}" />
            <jsp:param name="value" value="${signedAttributes.contentIdentifier.value}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.ContentIdentifier" />
        </jsp:include>
        
        <c:set var="multi" value="${signedAttributes.commitmentTypeIndication}" scope="request" />
        <spring:message code="label.policy.commitmentTypeIndication" var="translation" />
        <jsp:include page="multi-value-constraints.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.commitmentTypeIndication.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.CommitmentTypeIndication" />
        </jsp:include>
        
        <spring:message code="label.policy.signerLocation" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.signerLocation.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.SignerLocation.Level" />
        </jsp:include>
        
        <c:set var="multi" value="${signedAttributes.claimedRoles}" scope="request" />
        <spring:message code="label.policy.claimedRoles" var="translation" />
        <jsp:include page="multi-value-constraints.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.claimedRoles.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.ClaimedRoles" />
        </jsp:include>
        
        <c:set var="multi" value="${signedAttributes.certifiedRoles}" scope="request" />
        <spring:message code="label.policy.certifiedRoles" var="translation" />
        <jsp:include page="multi-value-constraints.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.certifiedRoles.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.CertifiedRoles" />
        </jsp:include>

		<spring:message code="label.policy.content.timestamp" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signedAttributes.contentTimeStamp.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBind}.ContentTimeStamp.Level" />
        </jsp:include>

    </div>
</div>
<c:remove var="signedAttributes" />