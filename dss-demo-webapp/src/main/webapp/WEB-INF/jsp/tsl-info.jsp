<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<h2>
    <spring:message code="label.tsls" />
</h2>

<c:set var="totalCerts" value="0" />
<c:forEach var="tslReport" items="${diagnosticInfo}">
    <c:set var="panelStyle" value="" />
    <c:choose>
        <c:when test="${!tslReport.loaded}">
            <c:set var="panelStyle" value="panel-danger" />
        </c:when>
        <c:when test="${!tslReport.allCertificatesLoaded}">
            <c:set var="panelStyle" value="panel-warning" />
        </c:when>
        <c:otherwise>
            <c:set var="panelStyle" value="panel-success" />
        </c:otherwise>
    </c:choose>
        
    <div class="panel ${panelStyle}">
        <div class="panel-heading" data-toggle="collapse" data-target="#country${tslReport.country}">
            <span class="badge pull-right">${fn:length(tslReport.certificates)} Cert(s)</span>
            <c:set var="totalCerts" value="${totalCerts + fn:length(tslReport.certificates)}" />
            <h3 class="panel-title">${tslReport.country}</h3>
        </div>
        <div class="panel-body collapse in" id="country${tslReport.country}">
            <dl class="dl-horizontal">
                <dt>Url : </dt>
                <dd><a href="${tslReport.url}">${tslReport.url}</a></dd>
                
                <c:if test="${tslReport.loadedDate !=null}">
                    <dt>Loaded date : </dt>
                    <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${tslReport.loadedDate}" /></dd>
                </c:if>
            </dl>
            
            <c:if test="${tslReport.loaded}">
                <div class="panel panel-default">
                    <div class="panel-heading" data-toggle="collapse" data-target="#certscountry${tslReport.country}">
                        <h3 class="panel-title">Loaded certificate(s)</h3>
                    </div>
                    <div class="panel-body collapse in" id="certscountry${tslReport.country}">
                        <c:forEach var="x509Certificate" items="${tslReport.certificates}">
                            <dl class="dl-horizontal">
                                <dt><spring:message code="label.service" /></dt>
                                <dd>${x509Certificate.certificate.subjectDN.name}</dd>
                                <dt><spring:message code="label.issuer" /></dt>
                                <dd>${x509Certificate.certificate.issuerDN.name}</dd>
                                <dt>Serial number</dt>
                                <dd>${x509Certificate.serialNumber}</dd>
                                <dt><spring:message code="label.validity_start" /></dt>
                                <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${x509Certificate.certificate.notBefore}" /></dd>
                                <dt><spring:message code="label.validity_end" /></dt>
                                <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${x509Certificate.certificate.notAfter}" /></dd>
                                <dt>Self-sign</dt>
                                <dd>
                                    <c:choose>
                                        <c:when test="${x509Certificate.selfSigned}"><span class="glyphicon glyphicon-ok"></span></c:when>
                                        <c:otherwise><span class="glyphicon glyphicon-remove"></span></c:otherwise>
                                    </c:choose>
                                </dd>
                            </dl>
                        </c:forEach>
                    </div>
                </div>
            </c:if>
        </div>
    </div>
</c:forEach>

<script type="text/javascript">
	$('.collapse').collapse();
</script>
