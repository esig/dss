<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
    <spring:message code="label.preferences" />
</h2>
<table class="table">
    <thead>
        <tr>
            <th><spring:message code="label.key" /></th>
            <th><spring:message code="label.value" /></th>
        </tr>
    </thead>
    <tbody>
        <c:forEach items="${preferences}" var="preference">
            <tr>
                <td><a href="<spring:url value="/admin/proxy/edit?key=${preference.proxyKey.keyName}"/>"><spring:message code="${preference.proxyKey.keyName}" /></a></td>
                <td><a href="<spring:url value="/admin/proxy/edit?key=${preference.proxyKey.keyName}"/>">${preference.value}</a></td>
            </tr>
        </c:forEach>
    </tbody>
</table>
