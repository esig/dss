<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jstl/fmt" prefix="fmt"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h1><spring:message code="label.preferences"/></h1>
<div class="fluid-row">
	<div class="fluid-column fluid-c12">
		<div class="common-box">
			<form:form method="post" commandName="preferenceForm" action="edit" cssClass="common-form label-on-left">
				<form:hidden path="key"/>			
				<fieldset>
					<div>
						<form:label path="value"><spring:message code="${preferenceForm.key}"/></form:label>
						<form:input path="value" size="100" maxlength="100" cssStyle="width:250px;"/>
					</div>
					<div class="button-container">
						<input type="submit" class="button" value="<spring:message code="label.update"/>">
					</div>
				</fieldset>
			</form:form>
		</div>		
	</div>
</div>


