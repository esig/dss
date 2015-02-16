<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>


<tiles:useAttribute name="jsFiles" id="jsFiles" classname="java.util.List"/>
<c:forEach items="${jsFiles}" var="jsFile">
	<script src="<%=request.getContextPath()%><c:out value='${jsFile}' />"></script>
</c:forEach>
