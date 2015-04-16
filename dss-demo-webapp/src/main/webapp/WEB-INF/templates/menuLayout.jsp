<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<ul role="navigation">
    <c:set var="currentPage" value="${requestScope['javax.servlet.forward.servlet_path']}" />
    <c:choose> 
        <%-- ADMIN PART --%>
        <c:when test="${fn:contains(currentPage, 'admin')}">
            <li class="${currentPage eq '/admin/general' ? 'selected' : ''}">
                <a href="<spring:url value="/admin/general"/>"><spring:message code="label.general" /></a>
            </li>
            <li class="${currentPage eq '/admin/proxy' ? 'selected' : ''}">
                <a href="<spring:url value="/admin/proxy"/>"><spring:message code="label.proxy" /></a>
            </li>
            <li class="${currentPage eq '/admin/tsl-info' ? 'selected' : ''}">
                <a href="<spring:url value="/admin/tsl-info"/>"><spring:message code="label.tsl" /></a>
            </li>
        </c:when>
        <%-- NO ADMIN PART --%>
        <c:otherwise>
            <li class="${currentPage eq '/signature' ? 'selected' : ''}">
                <a href="<spring:url value="/signature"/>"><spring:message code="label.signature.applet" /></a>
            </li>
            <li>
                <a href="https://joinup.ec.europa.eu/software/tlmanager/release/all"><spring:message code="label.tlmanager.tl.eu" /></a> 
            </li>
        </c:otherwise>
    </c:choose>
</ul>
