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
        
        <div class="form-group levelConstraints">
            <label class="col-sm-5 control-label"><spring:message code="label.policy.keyUsage" /></label>
        
            <div class="col-sm-7" style="margin-bottom: 15px;">
                <select class="form-control" name="${param.pathToBindPrefix}.KeyUsage.Level">
                    <option></option>
                    <option<c:if test="${currentCertificate.keyUsage.level == 'FAIL'}"> selected="selected"</c:if>>FAIL</option>
                    <option<c:if test="${currentCertificate.keyUsage.level == 'WARN'}"> selected="selected"</c:if>>WARN</option>
                    <option<c:if test="${currentCertificate.keyUsage.level == 'INFORM'}"> selected="selected"</c:if>>INFORM</option>
                    <option<c:if test="${currentCertificate.keyUsage.level == 'IGNORE'}"> selected="selected"</c:if>>IGNORE</option>
                </select>
            </div>
        
            <div class="col-sm-7 col-sm-offset-5">
                <c:forEach var="keyUsage" items="${keyUsages}" varStatus="loop">
                    <c:set var="checked" value="false" />
                    <c:forEach var="item" items="${currentCertificate.keyUsage.id}">
                        <c:if test="${item == keyUsage}"><c:set var="checked" value="true" /></c:if>
                    </c:forEach>
                    <input type="checkbox" name="${param.pathToBindPrefix}.KeyUsage.Id[${loop.index}]" value="${keyUsage}" <c:if test="${checked == true}"> checked="checked"</c:if> /> ${keyUsage}<br/>
                </c:forEach>
            </div>
        </div>

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
    
        <c:set var="cryptographic" value="${currentCertificate.cryptographic}" scope="request" />
        <jsp:include page="cryptographic-constraints.jsp">
            <jsp:param name="id" value="crypto-${param.id}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Cryptographic" />
        </jsp:include>
    </div>
</div>

<c:remove var="currentCertificate" />