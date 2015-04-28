<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
    <spring:message code="label.tsls" />
</h2>

<table class="table table-condensed">
    <thead>
        <tr>
            <th><spring:message code="label.tsl" /></th>
            <th><spring:message code="label.info" /></th>
        </tr>
    </thead>
    <tbody>
        <c:forEach items="${tsls}" var="tsl">
            <tr>
                <td>${tsl.key}</td>
                <td>${tsl.value}</td>
            </tr>
        </c:forEach>
    </tbody>
</table>

<h2>
   <spring:message code="label.certificates" />
</h2>
<c:forEach items="${certs}" var="x509Certificate">
    <dl class="dl-horizontal">
        <dt><spring:message code="label.service" /></dt>
        <dd>${x509Certificate.certificate.subjectDN.name}</dd>
        <dt><spring:message code="label.issuer" /></dt>
        <dd>${x509Certificate.certificate.issuerDN.name}</dd>
        <dt><spring:message code="label.validity_start" /></dt>
        <dd>${x509Certificate.certificate.notBefore}</dd>
        <dt><spring:message code="label.validity_end" /></dt>
        <dd>${x509Certificate.certificate.notAfter}</dd>
    </dl>
</c:forEach>
