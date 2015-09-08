<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<c:set var="currentPage" value="${requestScope['javax.servlet.forward.servlet_path']}" />

<c:choose> 
    <%-- ADMIN PART --%>
    <c:when test="${fn:contains(currentPage, 'admin')}">
        <div class="list-group hidden-print">
            <a href="<spring:url value="/admin/general"/>" class="list-group-item${currentPage eq '/admin/general' ? ' active' : ''}"><spring:message code="label.general" /></a>
            <a href="<spring:url value="/admin/proxy"/>" class="list-group-item${currentPage eq '/admin/proxy' ? ' active' : ''}"><spring:message code="label.proxy" /></a>
            <a href="<spring:url value="/admin/certificates"/>" class="list-group-item${currentPage eq '/admin/certificates' ? ' active' : ''}"><spring:message code="label.certificates" /></a>
        </div>
    </c:when>
    <%-- NO ADMIN PART --%>
    <c:otherwise>
        <div class="panel panel-default">
            <div class="panel-heading">e-Signature</div>
            <div class="list-group hidden-print">
                <a href="<spring:url value="/signature-light-applet" />" class="list-group-item${currentPage eq '/signature-light-applet' ? ' active' : ''}">Light applet + Spring MVC</a>
                <a href="<spring:url value="/signature-jnlp-webservices" />" class="list-group-item${currentPage eq '/signature-jnlp-webservices' ? ' active' : ''}">JNLP + SOAP WebServices</a>
                <a href="<spring:url value="/signature-standalone" />" class="list-group-item${currentPage eq '/signature-standalone' ? ' active' : ''}">Standalone application</a>
            </div>
        </div>
        <div class="panel panel-default">
            <div class="panel-heading">Server side</div>
            <div class="list-group hidden-print">
                <a href="<spring:url value="/extension" />" class="list-group-item${currentPage eq '/extension' ? ' active' : ''}"><spring:message code="label.extend" /></a>
                <a href="<spring:url value="/validation" />" class="list-group-item${currentPage eq '/validation' ? ' active' : ''}"><spring:message code="label.validate" /></a>
                <a href="<spring:url value="/validation-policy" />" class="list-group-item${currentPage eq '/validation-policy' ? ' active' : ''}"><spring:message code="label.validation-policy" /></a>
                <a href="<spring:url value="/tsl-info"/>" class="list-group-item${currentPage eq '/tsl-info' ? ' active' : ''} ${!lotlOK ? 'list-group-item-warning' : ''}">
    	            <spring:message code="label.tsls" />
                    <c:if test="${!lotlOK}">
                        <span class="glyphicon glyphicon-warning-sign pull-right"></span>
                    </c:if>
                </a>
            </div>
        </div>
    </c:otherwise>
</c:choose>

<div class="panel panel-default">
    <div class="panel-heading">Useful links</div>
    <div class="list-group hidden-print">
        <a href="https://joinup.ec.europa.eu/asset/sd-dss/description" class="list-group-item">Joinup</a>
        <a href="https://github.com/esig/dss/" class="list-group-item" title="GitHub - Source code">Source code</a>
        <a href="https://esig-dss.atlassian.net/projects/DSS" class="list-group-item" title="Jira - Issue tracker">Report a bug</a>
        <a href="https://joinup.ec.europa.eu/software/tlmanager/release/all" class="list-group-item"><spring:message code="label.tlmanager.tl.eu" /></a>
     </div>     
</div>