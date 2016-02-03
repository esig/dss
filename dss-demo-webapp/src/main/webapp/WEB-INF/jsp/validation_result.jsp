<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn"%> 

<c:if test="${fn:length(reports) gt 1}">
	<div id="reportSelectorPanel">
		<div class="panel-heading clearfix">
		   <div class="pull-left">
		   		<table>
			   		<tr>
				   		<td style="padding:0 0 0 0;">Report of </td>
				   		<td style="padding:0 15px 0 10px;">
						<select class="form-control" id="reportSelector" onchange="signatureFileNameChange()">
							<c:forEach var="report" items="${reports}">
								<c:choose>
									<c:when test="${report == selected }">
										<option value="${report}" selected="selected">${report}</option>
									</c:when>
									<c:otherwise>
										<option value="${report}">${report}</option>
									</c:otherwise>
								</c:choose>
							</c:forEach>
						</select>
						</td>
					</tr>
				</table>
			</div>
		</div>
	</div>
</c:if>


<ul class="nav nav-tabs nav-justified hidden-print" id="tabsResult">
    <li role="presentation" class="active"><a href="#simple-report"><spring:message code="label.simple.report" /></a></li>
    <li role="presentation"><a href="#detailed-report"><spring:message code="label.detailed.report" /></a></li>
    <li role="presentation"><a href="#diagnostic-tree"><spring:message code="label.diagnostic.tree" /></a></li>
</ul>

<div class="tab-content" style="margin-top: 10px">

    <div role="tabpanel" class="tab-pane fade in active" id="simple-report">
        <div class="btn-group pull-right hidden-print" role="toolbar" style="margin : 4px;">
            <button type="button" class="btn btn-default" onclick="window.print();">
                <span class="glyphicon glyphicon-print"></span> Print
            </button>
            <a class="btn btn-default" href="<spring:url value="/validation/download-simple-report" />" role="button">
                <span class="glyphicon glyphicon-save-file"></span> Download as PDF
            </a>
        </div>

        <c:out value="${simpleReport}" escapeXml="false" />
    </div>
    <div role="tabpanel" class="tab-pane fade" id="detailed-report">
        <div class="btn-group pull-right hidden-print" role="toolbar" style="margin : 4px;">
            <button type="button" class="btn btn-default" onclick="window.print();">
                <span class="glyphicon glyphicon-print"></span> Print
            </button>
            <a class="btn btn-default" href="<spring:url value="/validation/download-detailed-report" />" role="button">
                <span class="glyphicon glyphicon-save-file"></span> Download as PDF
            </a>
        </div>
    
        <c:out value="${detailedReport}" escapeXml="false" />
    </div>
    <div role="tabpanel" class="tab-pane fade" id="diagnostic-tree">
        <jsp:include page="diagnosticTree.jsp" />
    </div>
</div>

<script type="text/javascript">
    $('#tabsResult a').click(function(e) {
        e.preventDefault()
        $(this).tab('show')
    });
    
    $('.collapse').collapse();
    
    function signatureFileNameChange() {
    	var select = document.getElementById("reportSelector");
    	var value = select.options[select.selectedIndex].value;
    	var url = "/dss-demo-webapp/validation/report?name="+value;
    	window.location.href = url;
    }
</script>