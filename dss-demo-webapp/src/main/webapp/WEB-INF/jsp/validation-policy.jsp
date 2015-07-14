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
    
    
        
        <c:set var="signature" value="${policy.mainSignature}" scope="request" />
        <jsp:include page="policy/signature-constraints.jsp" />
    
        <c:set var="timestamp" value="${policy.timestamp}" scope="request" />
        <jsp:include page="policy/timestamp-constraints.jsp" />
        
        <c:set var="revocation" value="${policy.revocation}" scope="request" />
        <jsp:include page="policy/revocation-constraints.jsp" />
        
    
    <input type="submit" />
</form:form>