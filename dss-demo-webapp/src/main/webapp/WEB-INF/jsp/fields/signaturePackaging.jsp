<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="form-group">
    <form:label path="signaturePackaging" cssClass="col-sm-2 control-label">
        <spring:message code="label.signature.packaging" />
    </form:label>
    <div class="col-sm-6">
        <c:forEach var="sigPack" items="${signaturePackagings}">
            <label class="radio-inline">
                <form:radiobutton path="signaturePackaging" value="${sigPack}" id="signaturePackaging-${sigPack}" /> <spring:message code="label.${sigPack}" />
            </label>
        </c:forEach>
    </div>
    <div class="col-xs-3">
        <form:errors path="signaturePackaging" cssClass="text-danger" />
    </div>
</div>