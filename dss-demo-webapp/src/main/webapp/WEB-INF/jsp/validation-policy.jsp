<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<form:form method="post" modelAttribute="policy"> 

    <div class="form-group">
        <label class="col-sm-3 control-label">
            <spring:message code="label.policy.name" /> :  
        </label>
        <div class="col-sm-9">
            <form:input path="name" cssClass="form-control" />
        </div>
    </div>

    <div class="form-group">
        <label class="col-sm-3 control-label">
            <spring:message code="label.policy.description" /> :  
        </label>
        <div class="col-sm-9">
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
        
        
    </c:if>
    
    <input type="submit" />
</form:form>