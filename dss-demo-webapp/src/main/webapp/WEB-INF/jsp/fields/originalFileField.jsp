<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<div class="form-group">
    <form:label path="originalFile" cssClass="col-sm-2 control-label">
        <spring:message code="label.original.file" />
    </form:label>
    <div class="col-sm-4">
        <form:input path="originalFile" type="file" />
    </div>
</div>