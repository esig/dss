<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#revocation-block">
        <h3 class="panel-title">
            <spring:message code="label.policy.revocation" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="revocation-block">
    
        <c:set var="currentTimeConstraint" value="${revocation.revocationFreshness}" scope="request" />
        <spring:message code="label.policy.revocationFreshness" var="translation" />
        <jsp:include page="time-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="Revocation.RevocationFreshness" />
        </jsp:include>
        
        <c:set var="currentCertificate" value="${revocation.signingCertificate}" scope="request" />
        <spring:message code="label.policy.signingCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="Revocation.SigningCertificate" />
        </jsp:include> 
        
        <c:set var="currentCertificate" value="${revocation.CACertificate}" scope="request" />
        <spring:message code="label.policy.caCertificate" var="translation" />
        <jsp:include page="certificate-constraints.jsp">
            <jsp:param name="title" value="${translation}" />
            <jsp:param name="pathToBindPrefix" value="Revocation.CACertificate" />
        </jsp:include>
        
    </div>
</div>    
<c:remove var="revocation" />