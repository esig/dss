<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="form-group">
    <form:label path="signatureLevel" cssClass="col-sm-2 control-label">
        <spring:message code="label.signature.level" />
    </form:label>
    <div class="col-xs-4">
        <form:select path="signatureLevel" cssClass="form-control input-sm" id="selectSignatureLevel">
        </form:select>
    </div>
    <div class="col-xs-4 col-md-offset-2">
        <form:errors path="signatureLevel" cssClass="text-danger" />
    </div>
</div>