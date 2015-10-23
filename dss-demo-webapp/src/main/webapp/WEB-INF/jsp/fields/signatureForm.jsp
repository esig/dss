<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="form-group">
    <form:label path="signatureForm" cssClass="col-sm-2 control-label">
        <spring:message code="label.signature.form" />
    </form:label>
    <div class="col-sm-6">
        <c:forEach var="sigForm" items="${signatureForms}">
            <label class="radio-inline">
                <form:radiobutton path="signatureForm" value="${sigForm}" /> <spring:message code="label.${sigForm}" />
            </label>
        </c:forEach>
    </div>
    <div class="col-xs-4">
        <form:errors path="signatureForm" cssClass="text-danger" />
    </div>
</div>

<div class="form-group" id="underlying-form-block">
    <form:label path="asicUnderlyingForm" cssClass="col-sm-2 control-label">
        <spring:message code="label.signature.underlying.form" />
    </form:label>
    <div class="col-sm-6">
        <label class="radio-inline">
            <form:radiobutton path="asicUnderlyingForm" value="XAdES" /> <spring:message code="label.XAdES" />
        </label>
        <label class="radio-inline">
            <form:radiobutton path="asicUnderlyingForm" value="CAdES" /> <spring:message code="label.CAdES" />
        </label>
    </div>
    <div class="col-xs-4">
        <form:errors path="asicUnderlyingForm" cssClass="text-danger" />
    </div>
</div>