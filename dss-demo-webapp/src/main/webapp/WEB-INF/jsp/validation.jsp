<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.validate"/></h2>
<form:form method="post" modelAttribute="validationForm" cssClass="form-horizontal" enctype="multipart/form-data">

    <jsp:include page="fields/signedFileField.jsp" />
    
    <jsp:include page="fields/originalFileField.jsp" />

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <form:radiobutton path="defaultPolicy" value="true" /> <spring:message code="label.validation.default.policy.file" />
        </div>
    </div>

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-4">
            <form:radiobutton path="defaultPolicy" value="false" /> <spring:message code="label.validation.custom.policy.file" /> :
        </div>

        <div class="col-sm-6">
            <c:choose>
                <c:when test="${defaultPolicy}">
                    <form:input path="policyFile" type="file" id="policyFile" />
                </c:when>
                <c:otherwise>
                    <form:input path="policyFile" type="file" id="policyFile" disabled="true" />
                </c:otherwise>
            </c:choose>
        </div>
    </div>

    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary"><spring:message code="label.submit"/></button>
            <button type="reset" class="btn"><spring:message code="label.clear"/></button>
        </div>
    </div>   
</form:form>

<script type="text/javascript">
    $('input[name="defaultPolicy"]:radio').change(function() {
        $('#policyFile').attr("disabled", this.value == 'true');
    });
</script>