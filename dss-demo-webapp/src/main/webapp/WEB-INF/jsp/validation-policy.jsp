<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>

<c:if test="${not empty xmlResult}">
    <textarea rows="10" cols="25"><c:out value="${xmlResult}" /></textarea>
</c:if>

<form:form method="post" modelAttribute="policy" cssClass="form-horizontal" id="policyForm">

    <div class="form-group">
        <label class="col-sm-4 control-label"> <spring:message code="label.policy.name" /> :
        </label>
        <div class="col-sm-8">
            <form:input path="name" cssClass="form-control" />
        </div>
    </div>

    <div class="form-group">
        <label class="col-sm-4 control-label"> <spring:message code="label.policy.description" /> :
        </label>
        <div class="col-sm-8">
            <form:textarea path="description" cssClass="form-control" rows="5" />
        </div>
    </div>

    <c:set var="signature" value="${policy.mainSignature}" scope="request" />
    <spring:message code="label.policy.title.signature" var="title" />
    <jsp:include page="policy/signature-constraints.jsp">
        <jsp:param name="id" value="signature" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="MainSignature" />
    </jsp:include>

    <c:set var="timestamp" value="${policy.timestamp}" scope="request" />
    <spring:message code="label.policy.timestamp" var="title" />
    <jsp:include page="policy/timestamp-constraints.jsp">
        <jsp:param name="id" value="timestamp" />
        <jsp:param name="title" value="${title}" />
        <jsp:param name="pathToBindPrefix" value="Timestamp" />
    </jsp:include>

    <c:set var="revocation" value="${policy.revocation}" scope="request" />
    <jsp:include page="policy/revocation-constraints.jsp" />

    <button type="button" id="save-button">Save</button>

</form:form>

<script type="text/javascript">
    $("#save-button").click(function() {
        // disable empty levelConstraints
        $("div.levelConstraints select").each(function(index) {
            // console.log( index + ": " + $( this ).text() );
            if ($(this).val() === '' || $(this).val() === null) {
                $(this).prop('disabled', true);
            }
        });

        $("#policyForm").submit();
    });
</script>