<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.preferences"/></h2>
<form:form method="post" commandName="preferenceForm" action="edit" cssClass="form-horizontal">
    <form:hidden path="key" />
    <div class="form-group">
        <form:label path="value" cssClass="col-sm-3 control-label">
            <spring:message code="${preferenceForm.key}" />
        </form:label>
        <div class="col-sm-6">
            <form:input path="value" cssClass="form-control" />
        </div>
    </div>
    <div class="form-group">
        <div class="col-sm-offset-3 col-sm-6">
            <button type="submit" class="btn btn-primary"><spring:message code="label.update"/></button>
        </div>
    </div>   
</form:form>
