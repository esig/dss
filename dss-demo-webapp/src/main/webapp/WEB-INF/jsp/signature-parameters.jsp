<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<h2><spring:message code="label.signADocument"/></h2>
<form:form method="post" modelAttribute="signatureDocumentForm" cssClass="form-horizontal" enctype="multipart/form-data">

    <input type="hidden" id="isSign" value="true" />

    <div class="form-group">
        <form:label path="documentToSign" cssClass="col-sm-2 control-label">
            <spring:message code="label.to.sign.file" />
        </form:label>
        <div class="col-sm-4">
            <form:input path="documentToSign" type="file" />
        </div>
        <div class="col-xs-4 col-md-offset-2">
            <form:errors path="documentToSign" cssClass="text-danger" />
        </div>
    </div>

    <jsp:include page="fields/signatureForm.jsp" />
    
    <jsp:include page="fields/signaturePackaging.jsp" />
    
    <jsp:include page="fields/signatureLevel.jsp" />

    <div class="form-group">
        <form:label path="digestAlgorithm" cssClass="col-sm-2 control-label">
            <spring:message code="label.digest.algorithm" />
        </form:label>
        <div class="col-sm-6">
            <c:forEach var="algo" items="${digestAlgos}" varStatus="loop">
                <label class="radio-inline"> <form:radiobutton path="digestAlgorithm" value="${algo}" /> ${algo}</label>
                <c:if test="${((loop.index+1) % 4) == 0}"><br /></c:if>
            </c:forEach>
        </div>
        <div class="col-xs-4">
            <form:errors path="digestAlgorithm" cssClass="text-danger" />
        </div>
    </div>

    <div class="form-group" id="token-param">
        <form:label path="token" cssClass="col-sm-2 control-label">
            <spring:message code="label.tokenType" />
        </form:label>
        <div class="col-sm-6">
            <c:forEach var="tokenType" items="${tokenTypes}">
                <label class="radio-inline"> <form:radiobutton path="token" value="${tokenType}" /> <spring:message code="label.${tokenType}" />
                </label>
            </c:forEach>
        </div>
        <div class="col-xs-4">
            <form:errors path="token" cssClass="text-danger" />
        </div>
    </div>
    
    <div class="form-group" id="pkcs-params">
        <label class="col-sm-2 control-label labelsPKCS11">
            <spring:message code="label.config.pkcs11" />
        </label>
        <label class="col-sm-2 control-label labelsPKCS12">
            <spring:message code="label.config.pkcs12" />
        </label>
        
        <div class="col-sm-10">
            <div class="row">
                <div class="col-sm-3">
                    <form:label path="pkcsFile" cssClass="labelsPKCS11"><spring:message code="label.pkcs11.file" /></form:label>
                    <form:label path="pkcsFile" cssClass="labelsPKCS12"><spring:message code="label.pkcs12.file" /></form:label>
                </div>
                <div class="col-sm-4">
                    <form:input path="pkcsFile" type="file" />
                </div>
                <div class="col-sm-3">
                    <form:errors path="pkcsFile" cssClass="text-danger" />
                </div>
            </div>
            <div class="row">
                <div class="col-sm-3">
                    <form:label path="pkcsPassword" cssClass="labelsPKCS11"><spring:message code="label.pkcs11.password" /></form:label>
                    <form:label path="pkcsPassword" cssClass="labelsPKCS12"><spring:message code="label.pkcs12.password" /></form:label>
                </div>
                <div class="col-sm-4">
                    <form:password path="pkcsPassword"/>
                </div>
                <div class="col-sm-3">
                    <form:errors path="pkcsPasswordValid" cssClass="text-danger" />
                </div>
            </div>
        </div>
    </div>
    
    <div class="form-group">
        <div class="col-sm-offset-2 col-sm-10">
            <button type="submit" class="btn btn-primary"><spring:message code="label.submit"/></button>
            <button type="reset" class="btn"><spring:message code="label.clear"/></button>
        </div>
    </div>   

</form:form>

<script type="text/javascript" src="<c:url value="/scripts/jsSignatureLevel.js" />"></script>

<script type="text/javascript">
    var selectedToken = $("input[type='radio'][name='token']:checked");
    if (selectedToken.length > 0) {
        displayOrHidePKCSParams(selectedToken.val());
    } else {
        displayOrHidePKCSParams("");
    }

    $("#token-param").on("change", "input[type=radio]", function() {
		displayOrHidePKCSParams($(this).val());
    });
    
    function displayOrHidePKCSParams(token) {
        if (token == 'PKCS11') {
		    $('#pkcs-params').show();
		    $('.labelsPKCS11').show();
		    $('.labelsPKCS12').hide();
		} else if (token == 'PKCS12') {
		    $('#pkcs-params').show();
		    $('.labelsPKCS11').hide();
		    $('.labelsPKCS12').show();
		} else{
		    $('#pkcs-params').hide();
		}
    }
</script>