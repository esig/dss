<%@page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
	<div class="panel-heading" data-toggle="collapse"
		data-target="#block-<c:out value="${param.id}" />">
		<h3 class="panel-title">
			<c:out value="${param.title}" />
		</h3>
	</div>
	<div class="panel-body collapse in"
		id="block-<c:out value="${param.id}" />">

		<c:if test="${param.id != 'countersignature'}">
			<spring:message code="label.policy.structuralValidation"
				var="translation" />
			<jsp:include page="level-constraint.jsp">
				<jsp:param name="label" value="${translation}" />
				<jsp:param name="levelValue"
					value="${signature.structuralValidation.level}" />
				<jsp:param name="pathToBind"
					value="${param.pathToBindPrefix}.StructuralValidation.Level" />
			</jsp:include>

			<div class="form-group levelConstraints">
				<label class="col-sm-5 control-label"><spring:message
						code="label.policy.acceptablePolicies" /></label>

				<div class="col-sm-7" style="margin-bottom: 15px;">
					<select class="form-control"
						name="<c:out value="${param.pathToBindPrefix}"/>.AcceptablePolicies.Level">
						<option></option>
						<option
							<c:if test="${signature.acceptablePolicies.level == 'FAIL'}"> selected="selected"</c:if>>FAIL</option>
						<option
							<c:if test="${signature.acceptablePolicies.level == 'WARN'}"> selected="selected"</c:if>>WARN</option>
						<option
							<c:if test="${signature.acceptablePolicies.level == 'INFORM'}"> selected="selected"</c:if>>INFORM</option>
						<option
							<c:if test="${signature.acceptablePolicies.level == 'IGNORE'}"> selected="selected"</c:if>>IGNORE</option>
					</select>
				</div>

				<div class="col-sm-7 col-sm-offset-5">
					<c:forEach var="supportedPolicy" items="${supportedPolicies}"
						varStatus="loop">
						<c:set var="checked" value="false" />
						<c:forEach var="item" items="${signature.acceptablePolicies.id}">
							<c:if test="${item == supportedPolicy}">
								<c:set var="checked" value="true" />
							</c:if>
						</c:forEach>
						<input type="checkbox"
							name="<c:out value="${param.pathToBindPrefix}"/>.AcceptablePolicies.Id[${loop.index}]"
							value="<c:out value="${supportedPolicy}" />"
							<c:if test="${checked == true}"> checked="checked"</c:if> />
						<c:out value="${supportedPolicy} " />
						<br />
					</c:forEach>
				</div>
			</div>
		</c:if>
		
		
		
		<spring:message code="label.policy.acceptableFormats" var="translation" />
		<c:set var="multi" value="${signature.acceptableFormats}" scope="request" />
        <jsp:include page="multi-value-constraints.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${signature.acceptableFormats.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.AcceptableFormats" />
        </jsp:include>

		<div >
			<c:set var="basicSignatureConstraints" value="${signature.basicSignatureConstraints}" scope="request" />
			<jsp:include page="basic-signature-constraint.jsp">
				<jsp:param name="id" value="basicSignatureConstraints-${param.id}" />
	            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.BasicSignatureConstraints" />
			</jsp:include>
		</div>

		<div >
			<c:set var="signedAttributes" value="${signature.signedAttributes}" scope="request" />
			<jsp:include page="signed-attributes-constraints.jsp">
				<jsp:param name="id" value="signedAttributes-${param.id}" />
	            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.SignedAttributes" />
			</jsp:include>
		</div>		
		<div >
			<c:set var="unsignedAttributes" value="${signature.unsignedAttributes}" scope="request" />
			<jsp:include page="unsigned-attributes-constraints.jsp">
				<jsp:param name="id" value="unsignedAttributes-${param.id}" />
	            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.UnsignedAttributes" />
			</jsp:include>
		</div>	
	</div>
</div>
<c:remove var="signature" />