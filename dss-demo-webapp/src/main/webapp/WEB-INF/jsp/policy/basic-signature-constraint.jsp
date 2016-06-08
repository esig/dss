<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
	<spring:message code="label.policy.title.basicSignatureConstraint"
		var="blockTitle" />
	<div class="panel-heading" data-toggle="collapse"
		data-target="#block-basic-signature-constraints-<c:out value="${param.id}" />">
		<h3 class="panel-title">
			<c:out value="${blockTitle}" />
		</h3>
	</div>
	<div class="panel-body collapse in"
		id="block-basic-signature-constraints-<c:out value="${param.id}" />">
		<spring:message code="label.policy.referenceDataExistence"
			var="translation" />
		<jsp:include page="level-constraint.jsp">
			<jsp:param name="label" value="${translation}" />
			<jsp:param name="levelValue"
				value="${basicSignatureConstraints.referenceDataExistence.level}" />
			<jsp:param name="pathToBind"
				value="${param.pathToBind}.ReferenceDataExistence.Level" />
		</jsp:include>
		
		<spring:message code="label.policy.referenceDataIntact"
			var="translation" /> 
		<jsp:include page="level-constraint.jsp">
			<jsp:param name="label" value="${translation}" />
			<jsp:param name="levelValue"
 				value="${basicSignatureConstraints.referenceDataIntact.level}" /> 
 			<jsp:param name="pathToBind"
				value="${param.pathToBind}.ReferenceDataIntact.Level" />
		</jsp:include>
		
		<spring:message code="label.policy.signatureIntact" var="translation" />
		<jsp:include page="level-constraint.jsp">
			<jsp:param name="label" value="${translation}" />
			<jsp:param name="levelValue"
 				value="${basicSignatureConstraints.signatureIntact.level}" /> 
			<jsp:param name="pathToBind"
				value="${param.pathToBind}.SignatureIntact.Level" />
		</jsp:include>
		
		<spring:message code="label.policy.signatureValid" var="translation" />
		<jsp:include page="level-constraint.jsp">
			<jsp:param name="label" value="${translation}" />
			<jsp:param name="levelValue"
 				value="${basicSignatureConstraints.signatureValid.level}" /> 
			<jsp:param name="pathToBind"
				value="${param.pathToBind}.SignatureValid.Level" />
		</jsp:include>
		
		<spring:message code="label.policy.prospectiveCertificateChain" var="translation" />
		<jsp:include page="level-constraint.jsp">
			<jsp:param name="label" value="${translation}" />
			<jsp:param name="levelValue"
 				value="${basicSignatureConstraints.prospectiveCertificateChain.level}" /> 
			<jsp:param name="pathToBind"
				value="${param.pathToBind}.ProspectiveCertificateChain.Level" />
		</jsp:include>
		
		<c:if test="${param.id != 'countersignature'}">
			<c:set var="currentCertificate"
 				value="${basicSignatureConstraints.signingCertificate}" scope="request" />
			<spring:message code="label.policy.signingCertificate"
				var="translation" />
			<jsp:include page="certificate-constraints.jsp">
				<jsp:param name="id" value="signing-cert-signature" />
				<jsp:param name="title" value="${translation}" />
				<jsp:param name="pathToBindPrefix"
					value="${param.pathToBind}.SigningCertificate" />
			</jsp:include>

			<c:set var="currentCertificate" value="${basicSignatureConstraints.CACertificate}"
				scope="request" />
			<spring:message code="label.policy.caCertificate" var="translation" />
			<jsp:include page="certificate-constraints.jsp">
				<jsp:param name="id" value="ca-cert-signature" />
				<jsp:param name="title" value="${translation}" />
				<jsp:param name="pathToBindPrefix"
					value="${param.pathToBind}.CACertificate" />
			</jsp:include>
			
			<c:set var="cryptographic" value="${basicSignatureConstraints.cryptographic}" scope="request" />
	        <jsp:include page="cryptographic-constraints.jsp">
	            <jsp:param name="id" value="crypto-${param.id}" />
	            <jsp:param name="prefixPath" value="${param.pathToBind}.Cryptographic" />
	        </jsp:include>

		</c:if>
	</div>
</div>