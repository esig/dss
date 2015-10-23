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

        <c:if test="${param.id != 'countersignature'}">
            <spring:message code="label.policy.structuralValidation" var="translation" />
            <jsp:include page="level-constraint.jsp">
                <jsp:param name="label" value="${translation}" />
                <jsp:param name="levelValue" value="${signature.structuralValidation.level}" />
                <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.StructuralValidation.Level" />
            </jsp:include>

            <div class="form-group levelConstraints">
                <label class="col-sm-5 control-label"><spring:message code="label.policy.acceptablePolicies" /></label>

                <div class="col-sm-7" style="margin-bottom: 15px;">
                    <select class="form-control" name="${param.pathToBindPrefix}.AcceptablePolicies.Level">
                        <option></option>
                        <option <c:if test="${signature.acceptablePolicies.level == 'FAIL'}"> selected="selected"</c:if>>FAIL</option>
                        <option <c:if test="${signature.acceptablePolicies.level == 'WARN'}"> selected="selected"</c:if>>WARN</option>
                        <option <c:if test="${signature.acceptablePolicies.level == 'INFORM'}"> selected="selected"</c:if>>INFORM</option>
                        <option <c:if test="${signature.acceptablePolicies.level == 'IGNORE'}"> selected="selected"</c:if>>IGNORE</option>
                    </select>
                </div>

                <div class="col-sm-7 col-sm-offset-5">
                    <c:forEach var="supportedPolicy" items="${supportedPolicies}" varStatus="loop">
                        <c:set var="checked" value="false" />
                        <c:forEach var="item" items="${signature.acceptablePolicies.id}">
                            <c:if test="${item == supportedPolicy}">
                                <c:set var="checked" value="true" />
                            </c:if>
                        </c:forEach>
                        <input type="checkbox" name="${param.pathToBindPrefix}.AcceptablePolicies.Id[${loop.index}]" value="${supportedPolicy}" <c:if test="${checked == true}"> checked="checked"</c:if> /> ${supportedPolicy}<br />
                    </c:forEach>
                </div>
            </div>
        </c:if>
        
        <spring:message code="label.policy.referenceDataExistence" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataExistence.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.ReferenceDataExistence.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.referenceDataIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.referenceDataIntact.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.ReferenceDataIntact.Level" />
        </jsp:include>
        
        <spring:message code="label.policy.signatureIntact" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.signatureIntact.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.SignatureIntact.Level" />
        </jsp:include>
        
        <c:if test="${param.id != 'countersignature'}">
            <c:set var="currentCertificate" value="${signature.signingCertificate}" scope="request" />
            <spring:message code="label.policy.signingCertificate" var="translation" />
            <jsp:include page="certificate-constraints.jsp">
                <jsp:param name="id" value="signing-cert-signature" />
                <jsp:param name="title" value="${translation}" />
                <jsp:param name="pathToBindPrefix" value="${param.pathToBindPrefix}.SigningCertificate" />
            </jsp:include>
            
            <c:set var="currentCertificate" value="${signature.CACertificate}" scope="request" />
            <spring:message code="label.policy.caCertificate" var="translation" />
            <jsp:include page="certificate-constraints.jsp">
                <jsp:param name="id" value="ca-cert-signature" />
                <jsp:param name="title" value="${translation}" />
                <jsp:param name="pathToBindPrefix" value="${param.pathToBindPrefix}.CACertificate" />
            </jsp:include>
            
            <c:set var="signedAttributes" value="${signature.mandatedSignedQProperties}" scope="request" />
            <jsp:include page="signed-attributes-constraints.jsp" />
            
            <c:set var="unsignedAttributes" value="${signature.mandatedUnsignedQProperties}" scope="request" />
            <jsp:include page="unsigned-attributes-constraints.jsp" />
            
<%--             <c:set var="cryptographic" value="${signature.cryptographic}" scope="request" /> --%>
<%--             <jsp:include page="cryptographic-constraints.jsp" /> --%>
        </c:if>
    </div>
</div>
<c:remove var="signature" />