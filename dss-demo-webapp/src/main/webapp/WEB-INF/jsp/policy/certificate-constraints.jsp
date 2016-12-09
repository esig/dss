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
        <spring:message code="label.policy.recognition" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.recognition.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.Recognition.Level" />
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
            <jsp:param name="levelValue" value="${currentCertificate.notExpired.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.NotExpired.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.revocationDataAvailable" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataAvailable.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataAvailable.Level" />
        </jsp:include>

        <spring:message code="label.policy.revocationNextUpdatePresent" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataNextUpdatePresent.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataNextUpdatePresent.Level" />
        </jsp:include>

        <spring:message code="label.policy.revocationDataFreshness" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.revocationDataFreshness.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.RevocationDataFreshness.Level" />
        </jsp:include>
        
        <div class="form-group levelConstraints">
            <label class="col-sm-5 control-label"><spring:message code="label.policy.keyUsage" /></label>
        
            <div class="col-sm-7" style="margin-bottom: 15px;">
                <select class="form-control" name="<c:out value="${param.pathToBindPrefix}"/>.KeyUsage.Level">
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
                    <input type="checkbox" name="<c:out value="${param.pathToBindPrefix}"/>.KeyUsage.Id[${loop.index}]" value="${keyUsage}" <c:if test="${checked == true}"> checked="checked"</c:if> /> <c:out value="${keyUsage}" /><br/>
                </c:forEach>
            </div>
        </div>
        
        <spring:message code="label.policy.revoked" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.notRevoked.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.NotRevoked.Level" />
        </jsp:include>

        <spring:message code="label.policy.onHold" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${currentCertificate.notOnHold.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.NotOnHold.Level" />
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
            <jsp:param name="prefixPath" value="${param.pathToBindPrefix}.Cryptographic" />
        </jsp:include>
    </div>
</div>

<c:remove var="currentCertificate" />