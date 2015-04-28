<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>

<div class="alert alert-danger" role="alert">
	<strong>An error occurred ! </strong> <c:out value="${exception.message}" />
</div>

<!--
  Failed URL: ${url}
  Exception:  ${exception.message}
  
  <c:forEach var="ste" items="${exception.stackTrace}">
  	${ste} 
  </c:forEach>
-->