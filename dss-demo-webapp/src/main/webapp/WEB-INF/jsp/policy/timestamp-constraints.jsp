<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">
            <spring:message code="label.policy.timestamp" />
        </h3>
    </div>
    <div class="panel-body">
        <% // TODO TimestampDelay %>

        <spring:message code="label.policy.messageImprintDataFound" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.messageImprintDataFound.level}" />
            <jsp:param name="pathToBind" value="Timestamp.MessageImprintDataFound.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.messageImprintDataIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.messageImprintDataIntact.level}" />
            <jsp:param name="pathToBind" value="Timestamp.MessageImprintDataIntact.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.revocationTimeAgainstBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.revocationTimeAgainstBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="Timestamp.RevocationTimeAgainstBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.bestSignatureTimeBeforeIssuanceDateOfSigningCertificate" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.bestSignatureTimeBeforeIssuanceDateOfSigningCertificate.level}" />
            <jsp:param name="pathToBind" value="Timestamp.BestSignatureTimeBeforeIssuanceDateOfSigningCertificate.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signingCertificateValidityAtBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.signingCertificateValidityAtBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="Timestamp.SigningCertificateValidityAtBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.algorithmReliableAtBestSignatureTime" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.algorithmReliableAtBestSignatureTime.level}" />
            <jsp:param name="pathToBind" value="Timestamp.AlgorithmReliableAtBestSignatureTime.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.coherence" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${timestamp.coherence.level}" />
            <jsp:param name="pathToBind" value="Timestamp.Coherence.Level" />
        </jsp:include>
        
        <c:set var="currentCertificate" value="${timestamp.signingCertificate}" scope="request" />
        <spring:message code="label.policy.signingCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="Timestamp.SigningCertificate" />
        </jsp:include> 
        
        <c:set var="currentCertificate" value="${timestamp.CACertificate}" scope="request" />
        <spring:message code="label.policy.caCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="Timestamp.CACertificate" />
        </jsp:include>
        
        
    </div>
</div>    
<c:remove var="timestamp" />