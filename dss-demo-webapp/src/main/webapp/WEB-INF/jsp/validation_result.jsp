<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div role="tabpanel">
    <ul class="nav nav-tabs nav-justified" id="tabsResult">
        <li role="presentation" class="active"><a href="#simple-report"><spring:message code="label.simple.report" /></a></li>
        <li role="presentation"><a href="#detailed-report"><spring:message code="label.detailed.report" /></a></li>
        <li role="presentation"><a href="#diagnostic-tree"><spring:message code="label.diagnostic.tree" /></a></li>
    </ul>

    <div class="tab-content">
        <div role="tabpanel" class="tab-pane fade in active" id="simple-report">
            <p>Simple report</p>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="detailed-report">
            <p>Detailed report</p>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="diagnostic-tree">
            <jsp:include page="diagnosticTree.jsp" />
        </div>
    </div>
</div>

<script type="text/javascript">
    $('#tabsResult a').click(function(e) {
        e.preventDefault()
        $(this).tab('show')
    });
</script>