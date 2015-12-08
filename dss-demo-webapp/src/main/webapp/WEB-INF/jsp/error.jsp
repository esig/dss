<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="alert alert-danger" role="alert">
	<strong>An error occurred ! </strong> <c:out value="${exception.message}" escapeXml="true" />
</div>

<!--
  Failed URL: <c:out value="${url}" escapeXml="true" />
  Exception:  <c:out value="${exception.message}" escapeXml="true" />
  
  <c:forEach var="ste" items="${exception.stackTrace}">
  	<c:out value="${ste}" escapeXml="true" />
  </c:forEach>
-->