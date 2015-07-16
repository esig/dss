<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.extend"/></h2>
<form:form method="post" modelAttribute="extensionForm" cssClass="form-horizontal" enctype="multipart/form-data">
    
    <input type="hidden" id="isSign" value="false" />

    <jsp:include page="fields/signedFileField.jsp" />
    
    <jsp:include page="fields/originalFileField.jsp" />
    
    <jsp:include page="fields/signatureForm.jsp" />
    
    <jsp:include page="fields/signaturePackaging.jsp" />
    
    <jsp:include page="fields/signatureLevel.jsp" />
    
    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary"><spring:message code="label.submit"/></button>
            <button type="reset" class="btn"><spring:message code="label.clear"/></button>
        </div>
    </div>   
</form:form>


<script type="text/javascript" src="<c:url value="/scripts/jsSignatureLevel.js" />"></script>