<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<form:form method="post" modelAttribute="policy" cssClass="form-horizontal"> 

    <div class="form-group">
        <label class="col-sm-4 control-label">
            <spring:message code="label.policy.name" /> :  
        </label>
        <div class="col-sm-8">
            <form:input path="name" cssClass="form-control" />
        </div>
    </div>

    <div class="form-group">
        <label class="col-sm-4 control-label">
            <spring:message code="label.policy.description" /> :  
        </label>
        <div class="col-sm-8">
            <form:textarea path="description" cssClass="form-control" rows="5" />
        </div>
    </div>
    
    <c:set var="sig" value="${policy.mainSignature}" />
    
    
    <c:if test="${sig != null}">
    
        <c:set var="multiValuesConstraint" value="${sig.acceptablePolicies}" scope="request" />
        <spring:message code="label.policy.acceptablePolicies" var="translation" />
        <jsp:include page="policy/multi-values-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param value="pathToBind" name="mainSignature.acceptablePolicies"/>
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataExistence" var="translation" />
        <jsp:include page="policy/level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${sig.referenceDataExistence.level}" />
            <jsp:param name="pathToBind" value="MainSignature.ReferenceDataExistence.Level"/>
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataIntact" var="translation" />
        <jsp:include page="policy/level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${sig.referenceDataIntact.level}" />
            <jsp:param name="pathToBind" value="MainSignature.ReferenceDataIntact.Level"/>
        </jsp:include>
        
        <spring:message code="label.policy.signatureIntact" var="translation" />
        <jsp:include page="policy/level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${sig.signatureIntact.level}" />
            <jsp:param name="pathToBind" value="MainSignature.SignatureIntact.Level"/>
        </jsp:include>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title"><spring:message code="label.policy.signingCertificate" /></h3>
            </div>
            <div class="panel-body">
            
                <c:set var="signingCertificate" value="${sig.signingCertificate}" />

                <spring:message code="label.policy.recognition" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.recognition.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Recognition.Level" />
                </jsp:include>

                <spring:message code="label.policy.attributePresent" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.attributePresent.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.AttributePresent.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.digestValuePresent" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.digestValuePresent.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.DigestValuePresent.Level" />
                </jsp:include>

                <spring:message code="label.policy.digestValueMatch" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.digestValueMatch.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.DigestValueMatch.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.issuerSerialMatch" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.issuerSerialMatch.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.IssuerSerialMatch.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.signed" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.signed.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Signed.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.signature" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.signature.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Signature.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.expiration" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.expiration.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Expiration.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.revocationDataAvailable" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.revocationDataAvailable.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.RevocationDataAvailable.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.revocationDataIsTrusted" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.revocationDataIsTrusted.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.RevocationDataIsTrusted.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.revocationDataFreshness" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.revocationDataFreshness.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.RevocationDataFreshness.Level" />
                </jsp:include>
                
                <% // TODO keyusage %>
                
                <spring:message code="label.policy.revoked" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.revoked.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Revoked.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.onHold" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.onHold.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.OnHold.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.tslValidity" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.TSLValidity.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.TSLValidity.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.tslStatus" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.TSLStatus.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.TSLStatus.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.qualification" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.qualification.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.Qualification.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.supportedBySSCD" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.supportedBySSCD.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.SupportedBySSCD.Level" />
                </jsp:include>
                
                <spring:message code="label.policy.issuedToLegalPerson" var="translation" />
                <jsp:include page="policy/level-constraint.jsp">
                    <jsp:param name="label" value="${translation}" />
                    <jsp:param name="levelValue" value="${signingCertificate.issuedToLegalPerson.level}" />
                    <jsp:param name="pathToBind" value="MainSignature.SigningCertificate.IssuedToLegalPerson.Level" />
                </jsp:include>
                
        </c:if>
    
    <input type="submit" />
</form:form>