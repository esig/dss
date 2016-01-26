<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="form-group levelConstraints">
    <label class="col-sm-5 control-label"><c:out value="${param.label}" /></label>
	
	<div class="col-sm-7" style="margin-bottom: 15px;">
		<input class="form-control" name="<c:out value="${param.pathToBind}.Value"/>" value="<c:out value="${param.value}"/>" />
	</div>	
	<div class="col-sm-7 col-sm-offset-5">	
		<select class="form-control" name="<c:out value="${param.pathToBind}.Level"/>">
            <option></option>
            <option<c:if test="${param.levelValue == 'FAIL'}"> selected="selected"</c:if>>FAIL</option>
            <option<c:if test="${param.levelValue == 'WARN'}"> selected="selected"</c:if>>WARN</option>
            <option<c:if test="${param.levelValue == 'INFORM'}"> selected="selected"</c:if>>INFORM</option>
            <option<c:if test="${param.levelValue == 'IGNORE'}"> selected="selected"</c:if>>IGNORE</option>
        </select>
	</div>
</div>