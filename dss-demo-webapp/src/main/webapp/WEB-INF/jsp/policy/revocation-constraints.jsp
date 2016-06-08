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

        <div >
			<c:set var="basicSignatureConstraints" value="${revocation.basicSignatureConstraints}" scope="request" />
			<jsp:include page="basic-signature-constraint.jsp">
				<jsp:param name="id" value="basicSignatureConstraints-${param.id}" />
	            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.BasicSignatureConstraints" />
			</jsp:include>
		</div>
        
    </div>
</div>    
<c:remove var="revocation" />