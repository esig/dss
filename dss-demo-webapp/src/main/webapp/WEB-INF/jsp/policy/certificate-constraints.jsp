<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>


<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">
            ${param.title}
        </h3>
    </div>
    <div class="panel-body">

        <spring:message code="label.policy.recognition" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.recognition.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Recognition.Level" />
        </jsp:include>

        <spring:message code="label.policy.attributePresent" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.attributePresent.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.AttributePresent.Level" />
        </jsp:include>

        <spring:message code="label.policy.digestValuePresent" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.digestValuePresent.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.DigestValuePresent.Level" />
        </jsp:include>

        <spring:message code="label.policy.digestValueMatch" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.digestValueMatch.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.DigestValueMatch.Level" />
        </jsp:include>

        <spring:message code="label.policy.issuerSerialMatch" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.issuerSerialMatch.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.IssuerSerialMatch.Level" />
        </jsp:include>

        <spring:message code="label.policy.signed" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.signed.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Signed.Level" />
        </jsp:include>

        <spring:message code="label.policy.signature" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.signature.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Signature.Level" />
        </jsp:include>

        <spring:message code="label.policy.expiration" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.expiration.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Expiration.Level" />
        </jsp:include>

        <spring:message code="label.policy.revocationDataAvailable" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataAvailable.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataAvailable.Level" />
        </jsp:include>

        <spring:message code="label.policy.revocationDataIsTrusted" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataIsTrusted.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataIsTrusted.Level" />
        </jsp:include>

        <spring:message code="label.policy.revocationDataFreshness" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataFreshness.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataFreshness.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.prospectiveCertificateChain" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.prospectiveCertificateChain.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.ProspectiveCertificateChain.Level" />
        </jsp:include>
        
        <% // TODO keyusage %>

        <spring:message code="label.policy.revoked" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revoked.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Revoked.Level" />
        </jsp:include>

        <spring:message code="label.policy.onHold" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.onHold.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.OnHold.Level" />
        </jsp:include>

        <spring:message code="label.policy.tslValidity" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.TSLValidity.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.TSLValidity.Level" />
        </jsp:include>

        <spring:message code="label.policy.tslStatus" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.TSLStatus.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.TSLStatus.Level" />
        </jsp:include>

        <spring:message code="label.policy.tslStatusAndValidity" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.TSLStatusAndValidity.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.TSLStatusAndValidity.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.qualification" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.qualification.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Qualification.Level" />
        </jsp:include>

        <spring:message code="label.policy.supportedBySSCD" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.supportedBySSCD.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.SupportedBySSCD.Level" />
        </jsp:include>

        <spring:message code="label.policy.issuedToLegalPerson" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.issuedToLegalPerson.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.IssuedToLegalPerson.Level" />
        </jsp:include>
    </div>
</div>

<c:remove var="currentCertificate" />