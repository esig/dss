<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<div class="form-group">
    <form:label path="signedFile" cssClass="col-sm-2 control-label">
        <spring:message code="label.signed.file" />
    </form:label>
    <div class="col-sm-4">
        <form:input path="signedFile" type="file" /> 
    </div>
    <div class="col-xs-4 col-md-offset-2">
        <form:errors path="signedFile" cssClass="text-danger" />
    </div>
</div>