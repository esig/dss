<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>


<tiles:useAttribute name="menus" id="menus" classname="java.util.List"/>
<ul role="navigation">
	<c:forEach items="${menus}" var="menu">
		<li class="<c:if test="${fn:startsWith(requestScope['javax.servlet.forward.servlet_path'],menu.startWith)}">selected</c:if>">
			<a href="<spring:url value="${menu.url}"/>"><spring:message code="${menu.key}" /></a>
		</li>
	</c:forEach>	
</ul>

