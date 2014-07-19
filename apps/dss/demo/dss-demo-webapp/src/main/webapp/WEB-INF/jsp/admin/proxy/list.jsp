<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h1><spring:message code="label.preferences"/></h1>
<div class="fluid-row">
	<div class="fluid-column fluid-c12">
		<div class="table-container">
			<table class="data-table">
				<thead>
					<tr>
						<th style="width:20%;"><spring:message code="label.key"/></th>
						<th style="width:80%;"><spring:message code="label.value"/></th>
					</tr>
				</thead>
				<tbody>
					<c:forEach items="${preferences}" var="preference">
					<tr>
						<td><a href="<spring:url value="/admin/proxy/edit?key=${preference.proxyKey.keyName}"/>"><spring:message code="${preference.proxyKey.keyName}"/></a></td>
						<td><a href="<spring:url value="/admin/proxy/edit?key=${preference.proxyKey.keyName}"/>">${preference.value}</a></td>
					</tr>
					</c:forEach>
				</tbody>
			</table>		
		</div>
	</div>
</div>
