<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#block-<c:out value="${param.id}" />">
        <h3 class="panel-title">
            <c:out value="${param.title}" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="block-<c:out value="${param.id}" />">

        <c:set var="currentTimeConstraint" value="${timestamp.timestampDelay}" scope="request" />
        <spring:message code="label.policy.timestampDelay" var="translation" />
        <jsp:include page="time-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="${param.pathToBindPrefix}.TimestampDelay" />
        </jsp:include>

        <spring:message code="label.policy.messageImprintDataFound" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.messageImprintDataFound.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.MessageImprintDataFound.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.messageImprintDataIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.messageImprintDataIntact.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.MessageImprintDataIntact.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.revocationTimeAgainstBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.revocationTimeAgainstBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationTimeAgainstBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.bestSignatureTimeBeforeIssuanceDateOfSigningCertificate" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.bestSignatureTimeBeforeIssuanceDateOfSigningCertificate.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.BestSignatureTimeBeforeIssuanceDateOfSigningCertificate.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signingCertificateValidityAtBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.signingCertificateValidityAtBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.SigningCertificateValidityAtBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.algorithmReliableAtBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.algorithmReliableAtBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.AlgorithmReliableAtBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.coherence" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.coherence.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Coherence.Level" />
        </jsp:include>
        
        <div >
			<c:set var="basicSignatureConstraints" value="${timestamp.basicSignatureConstraints}" scope="request" />
			<jsp:include page="basic-signature-constraint.jsp">
				<jsp:param name="id" value="basicSignatureConstraints-${param.id}" />
	            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.BasicSignatureConstraints" />
			</jsp:include>
		</div>
    </div>
</div>    
<c:remove var="timestamp" />