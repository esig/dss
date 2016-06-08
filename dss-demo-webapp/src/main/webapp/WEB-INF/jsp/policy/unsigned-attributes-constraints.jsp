<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#unsigned-attributes-block-<c:out value="${param.id}"/>">
        <h3 class="panel-title">
            <spring:message code="label.policy.unsignedAttributes" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="unsigned-attributes-block-<c:out value="${param.id}"/>">

		<spring:message code="label.policy.countersignature" var="translation" />
        <jsp:include page="level-constraint.jsp">
            <jsp:param name="label" value="${translation}" />
            <jsp:param name="levelValue" value="${unsignedAttributes.counterSignature.level}" />
            <jsp:param name="pathToBind" value="${param.pathToBindPrefix}.CounterSignature.Level" />
        </jsp:include>

    </div>
</div>

<c:remove var="unsignedAttributes" />