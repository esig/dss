<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2><spring:message code="label.signature.done"/></h2>
<h3><spring:message code="label.download.will.start" /></h3>


<script type="text/javascript">
	window.location="signature/download";
</script>