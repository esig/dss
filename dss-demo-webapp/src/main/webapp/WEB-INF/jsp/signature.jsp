<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
    <spring:message code="label.signature.applet" />
</h2>

<script src="//www.java.com/js/deployJava.js"></script>
<script type="text/javascript">
    var attributes = {
    	width: 800,
    	height :600
    };
    var parameters = {
        service_url : '<c:out value="${prefUrlService.value}"/>',
        default_policy_url : '<c:out value="${prefDefaultPolicyUrl}"/>',
        jnlp_href: 'jnlp/applet.jnlp'
    };
    var version = '1.6';
    deployJava.runApplet(attributes, parameters, version);
</script>


<jsp:include page="applet-warning.jsp" />