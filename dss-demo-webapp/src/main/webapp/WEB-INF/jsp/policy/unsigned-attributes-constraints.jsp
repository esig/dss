<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#unsigned-attributes-block">
        <h3 class="panel-title">
            <spring:message code="label.policy.unsignedAttributes" />
        </h3>
    </div>
    <div class="panel-body collapse in" id="unsigned-attributes-block">

        <c:set var="signature" value="${unsignedAttributes.counterSignature}" scope="request" />
        <spring:message code="label.policy.countersignature" var="title" />
        <jsp:include page="signature-constraints.jsp">
            <jsp:param name="id" value="countersignature" />
            <jsp:param name="title" value="${title}" />
            <jsp:param name="pathToBindPrefix" value="MainSignature.MandatedUnsignedQProperties.ContentTimeStamp" />
        </jsp:include>

    </div>
</div>

<c:remove var="unsignedAttributes" />