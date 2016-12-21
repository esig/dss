<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="form-group">
	<form:label path="containerType" cssClass="col-sm-2 control-label">
		<spring:message code="label.asic.container.type" />
	</form:label>
	<div class="col-sm-6">
		<c:forEach var="asicType" items="${asicContainerTypes}">
			<label class="radio-inline">
				<form:radiobutton path="containerType" value="${asicType}" /> <spring:message code="label.${asicType}" />
			</label>
		</c:forEach>
	</div>
	<div class="col-xs-4">
		<form:errors path="containerType" cssClass="text-danger" />
	</div>
</div>