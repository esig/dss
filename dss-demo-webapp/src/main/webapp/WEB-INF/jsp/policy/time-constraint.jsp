<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="form-group">
    <label class="col-sm-5 control-label">${param.label}</label>

    <div class="col-sm-3">
        <input class="form-control" name="${param.pathToBindPrefix}.value" value="${currentTimeConstraint.value}" />
    </div>
    <div class="col-sm-4">
        <select class="form-control" name="${param.pathToBindPrefix}.unit">
            <c:forEach var="timeUnit" items="${timeUnits}">
	           <option<c:if test="${timeUnit == currentTimeConstraint.unit}"> selected="selected"</c:if>>${timeUnit}</option>
            </c:forEach>
        </select>
    </div>
</div>

<c:remove var="currentTimeConstraint" />