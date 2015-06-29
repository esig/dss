<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
	<title><spring:message code="application.title" /></title>

    <!-- Bootstrap -->
    <link href="<c:url value="/css/bootstrap.min.css" />" rel="stylesheet" />
    <link href="<c:url value="/css/bootstrap-theme.min.css" />" rel="stylesheet" />
    <link href="<c:url value="/css/dss.css" />" rel="stylesheet" />
    
    <script type="text/javascript" src="<c:url value="/scripts/jquery-1.11.2.min.js" />"></script>
    <!-- Include all compiled plugins (below), or include individual files as needed -->
    <script type="text/javascript" src="<c:url value="/scripts/bootstrap.min.js" />"></script>
    <script type="text/javascript" src="<c:url value="/scripts/prettify.js" />"></script>
    <%--Used in signature.jsp --%>
    <script type="text/javascript" src="<c:url value="/scripts/detect_browser_version.js" />"></script>
  </head>
  <body>
       <nav class="navbar navbar-default hidden-print">
            <div class="container">
                <div class="navbar-header">
                    <a class="navbar-brand" href="<spring:url value="/home"/>">
                        <img src="<c:url value="/images/68x63-dss-logo.png" />" alt="Logo" title="<spring:message code="application.title" />" />
    	            </a>
                </div>
                <div class="collapse navbar-collapse">
                    <ul class="nav navbar-nav">
                        <li><a href="<spring:url value="/home"/>"><spring:message code="application.title" /></a></li>
                    </ul>
                    <ul class="nav navbar-nav navbar-right">
                        <li><a href="<spring:url value="/admin/general"/>"><spring:message code="label.administration" /></a></li>
                    </ul>
                </div>
            </div>
        </nav>
    
        <div class="container">
            <div class="row">
                <tiles:useAttribute name="hideMenu" />
                <c:choose>
                    <c:when test="${hideMenu eq 'true'}">
                        <div class="col-md-8 col-md-offset-2">
                            <tiles:insertAttribute name="content" />
                        </div>
                    </c:when>
                    <c:otherwise>
                        <div class="col-md-3">
                            <jsp:include page="menuLayout.jsp" />
                        </div>
                        <div class="col-md-9">
                            <tiles:insertAttribute name="content" />
                        </div>
                    </c:otherwise>
                </c:choose>
            </div>
        </div>
        
        <div class="container">
            <hr />
            <footer>
                <div class="row">
                    <div class="col-md-12">
                        <p class="text-right"><spring:message code="application.title"/> <spring:message code="application.version"/></p>
                    </div>
                </div>
            </footer>
        </div>
    </body>
</html>
