<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<h2>
    <spring:message code="label.tsls" />
</h2>

<jsp:useBean id="now" class="java.util.Date"/>

<table class="table">
	<thead>
		<tr>
			<th>Signature</th>
			<th>Country</th>
			<th>Seq N°</th>	
			<th>Check date</th>
			<th>Issue date</th>
			<th>Next update</th>
			<th>Nb of <abbr title="Trusted Service Providers">TSP</abbr></th>
			<th>Nb of <abbr title="Trusted Services">TS</abbr></th>
			<th>Nb of <abbr title="Trusted Certificates">Certs</abbr></th>
		</tr>
	</thead>
	<tbody>
		<c:forEach var="item" items="${summary}">
			<c:set var="rowStyle" value="" />
			<c:choose>
				<c:when test="${item.indication == 'INDETERMINATE' || item.nextUpdateDate le now}">
					<c:set var="rowStyle" value="warning" />
				</c:when>
				<c:when test="${item.indication == 'INVALID' }">
					<c:set var="rowStyle" value="danger" />
				</c:when>
			</c:choose>
		
			<tr class="${rowStyle}">
				<c:choose>
					<c:when test="${item.indication == 'VALID' }">
						<td class="text-center">
							<span class="glyphicon glyphicon-ok-sign text-success" title="valid"></span>
						</td>
					</c:when>
					<c:when test="${item.indication == 'INDETERMINATE' }">
						<td class="warning text-center"">
							<span class="glyphicon glyphicon-question-sign text-warning" title="indeterminate"></span>
						</td>
					</c:when>
					<c:when test="${item.indication == 'INVALID' }">
						<td class="danger text-center">
							<span class="glyphicon glyphicon-remove-sign text-danger" title="invalid"></span>
						</td>
					</c:when>
					<c:otherwise>
						<td>
						</td>
					</c:otherwise>
				</c:choose>
				<td class="text-center"><a href="<spring:url value="/tsl-info/${fn:toLowerCase(item.country)}" />">${item.country}</a></td>	
				<td class="text-center">${item.sequenceNumber}</td>
				<td>
					<c:if test="${item.loadedDate != null}">
						<fmt:formatDate pattern="HH:mm:ss" value="${item.loadedDate}" />
					</c:if>
				</td>
				<td>
					<c:if test="${item.issueDate != null}">
						<fmt:formatDate pattern="dd/MM/yyyy HH:mm" value="${item.issueDate}" />
					</c:if>
				</td>
				<td>
					<c:if test="${item.nextUpdateDate != null}">
						<c:choose>
							<c:when test="${item.nextUpdateDate le now}">
								<span class="text-danger"><strong><fmt:formatDate pattern="dd/MM/yyyy HH:mm" value="${item.nextUpdateDate}" /></strong></span>
							</c:when>
							<c:otherwise>
								<fmt:formatDate pattern="dd/MM/yyyy HH:mm" value="${item.nextUpdateDate}" />
							</c:otherwise>
						</c:choose>
					</c:if>
				</td>
				<td class="text-center">${item.nbServiceProviders}</td>
				<td class="text-center">${item.nbServices}</td>
				<td class="text-center">${item.nbCertificatesAndX500Principals}</td>
			</tr>		
		</c:forEach>
	</tbody>
</table>
