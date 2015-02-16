<!DOCTYPE html>
<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>


<html lang="en" xml:lang="en">
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
		<link rel="stylesheet" href="<c:url value="/css/reset.css" />" />
		<link rel="stylesheet" href="<c:url value="/css/template.css" />"/>
		<link rel="stylesheet" href="<c:url value="/css/dss.css" />"/>
		<tiles:insertAttribute name="jsFile" ignore="true" />
		<!--[if lte IE 8]>
		<link rel="stylesheet" href="<c:url value="/css/template-ie.css"/>">
		<script type="text/javascript"> activeHTML(); </script>
		<![endif]-->		
		<link rel="stylesheet" href="<c:url value="/css/template-mobile.css"/>" media="screen and (max-width: 900px)">		
		<link rel="shortcut icon" href="<c:url value="/images/favicon.ico"/>" />
		<link rel="icon" href="<c:url value="/images/favicon_animated.gif"/>" />
		<title><spring:message code="application.title" /></title>
	</head>

<body class="">
	<header class="full-row" role="banner">
    	<div class="full-column">
                <div class="logo">
                    <a href="<spring:url value="/home"/>"><img src="<c:url value="/images/68x63-dss-logo.png" />" align="Logo" /></a>
                </div>
                <span class="site-title">
                    <spring:message code="application.title" />
                </span>
                <div class="powered">
                    <span><a href="https://joinup.ec.europa.eu/software/sd-dss/description">Powered by DSS</a></span>
                </div>
        </div>
        <!--[if lte IE 8]><div class="deco">&nbsp;</div><![endif]-->
    </header>
    
    
	<nav id="horizontal-menu" class="full-row">
		<div class="full-column">    	
            <ul role="navigation">
                <li><a href="<spring:url value="/home"/>"><spring:message code="label.home"/></a>
                <li><a href="<spring:url value="/admin/general"/>"><spring:message code="label.administration"/></a></li>
            </ul>
        </div>
    </nav>
    <div class="full-row">
        <section id="content" class="full-column">
        	<tiles:useAttribute name="menu" id="menu" ignore="true"/>
        	<c:if test="${menu != null}">
            <nav id="inside-menu" class="left-column">
            	<div class="mobile-menu"><a class="down" href="javascript:;">MENU</a></div>
            	<tiles:insertAttribute name="menu"/>
            </nav>
            </c:if>
            <section id="main" role="main" class="middle-column">
				<tiles:insertAttribute name="content" />                
            </section> <!-- /#main -->
        </section> <!-- /#content -->
    </div>
    <footer role="contentinfo" class="full-row">
    	<div class="full-column">
            <p><spring:message code="application.title"/> <spring:message code="application.version"/> - Nowina 2015 &copy;</p>
        </div>
    </footer>

	<script type="text/javascript">
		$(document).ready(function(){
			window.scrollTo(0,1);
			$('a.down').live('click', function(){ 
				$('#inside-menu li').css({display:'block'});
				$('#inside-menu li[class!=selected]').css({display:'none'}).slideDown('slow');
				$(this).removeClass('down').addClass('up');
			});
			$('a.up').live('click', function(){ 
				$('#inside-menu li[class!=selected]').slideUp('slow');
				$(this).removeClass('up').addClass('down');
			});
		});
	</script>    

	</body>
</html>
