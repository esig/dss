<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="form-group">
    <label class="col-sm-4 control-label">${param.label}</label>

    <div class="col-sm-8">
        <select class="form-control" name="${param.pathToBind}">
            <option<c:if test="${param.levelValue == 'FAIL'}"> selected="selected"</c:if>>FAIL</option>
            <option<c:if test="${param.levelValue == 'WARN'}"> selected="selected"</c:if>>WARN</option>
            <option<c:if test="${param.levelValue == 'INFORM'}"> selected="selected"</c:if>>INFORM</option>
            <option<c:if test="${param.levelValue == 'IGNORE'}"> selected="selected"</c:if>>IGNORE</option>
        </select>
    </div>
</div>