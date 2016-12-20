<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="form-group">
	<form:label path="digestAlgorithm" cssClass="col-sm-2 control-label">
		<spring:message code="label.digest.algorithm" />
	</form:label>
	<div class="col-sm-6">
		<c:forEach var="algo" items="${digestAlgos}">
			<label class="radio-inline"> 
				<form:radiobutton path="digestAlgorithm" value="${algo}" /> ${algo}
			</label>
		</c:forEach>
	</div>
	<div class="col-xs-4">
		<form:errors path="digestAlgorithm" cssClass="text-danger" />
	</div>
</div>