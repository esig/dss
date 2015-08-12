<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>

<div class="panel panel-default">
    <div class="panel-heading">
        <span class="badge pull-right">${fn:length(keystoreCertificates)} Cert(s)</span>
        <h3 class="panel-title">
            <spring:message code="label.trusted.certificates.from.OJ" />
        </h3>
    </div>
    <div class="panel-body">
        <c:if test="${keystoreCertificates !=null}">
            <c:forEach var="certificateDTO" items="${keystoreCertificates}">
                <form method="post">
                    <input type="hidden" name="dssId" value="${certificateDTO.dssId}" />
                    <button type="submit" class="btn btn-default pull-right" aria-label="Left Align" name="delete">
                        <span class="glyphicon glyphicon-trash" aria-hidden="true"></span>
                    </button>
                </form>
                <dl class="dl-horizontal">
                    <dt><spring:message code="label.service" /></dt>
                    <dd>${certificateDTO.subjetName}</dd>
                    <dt><spring:message code="label.issuer" /></dt>
                    <dd>${certificateDTO.issuerName}</dd>
                    <dt><spring:message code="label.validity_start" /></dt>
                    <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${certificateDTO.notBefore}" /></dd>
                    <dt><spring:message code="label.validity_end" /></dt>
                    <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${certificateDTO.notAfter}" /></dd>

                    <dt>SHA-256 (Hex)</dt>
                    <dd>${certificateDTO.sha256Hex}</dd>
                    <dt>SHA-1 (Hex)</dt>
                    <dd>${certificateDTO.sha1Hex}</dd>
                    <dt>SHA-256 (Base64)</dt>
                    <dd>${certificateDTO.sha256Base64}</dd>
                    <dt>SHA-1 (Base64)</dt>
                    <dd>${certificateDTO.sha1Base64}</dd>
                </dl>
            </c:forEach>
        </c:if>
    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">
            <spring:message code="label.add.a.certificate.in.keystore" />
        </h3>
    </div>
    <div class="panel-body">
        <form:form method="post" modelAttribute="certificateForm" cssClass="form-horizontal" enctype="multipart/form-data">
            <div class="form-group">
                <form:label path="certificateFile" cssClass="col-sm-3 control-label">
                    <spring:message code="label.certificate.file" /> : 
                </form:label>
                <div class="col-sm-3">
                    <form:input path="certificateFile" type="file" /> 
                </div>
                <div class="col-xs-3 col-md-offset-1">
                    <form:errors path="certificateFile" cssClass="text-danger" />
                </div>
            </div>
            
            <div class="form-group">
                <form:label path="addToKeystore" cssClass="col-sm-3 control-label">
                    <spring:message code="label.add.to.keystore" /> : 
                </form:label>
                <div class="col-sm-4">
                    <form:checkbox path="addToKeystore" /> 
                </div>
            </div>
                        
            <c:if test="${certificateDTO !=null}">
            
                <dl class="dl-horizontal">
                
                    <dt><spring:message code="label.service" /></dt>
                    <dd>${certificateDTO.subjetName}</dd>
                    <dt><spring:message code="label.issuer" /></dt>
                    <dd>${certificateDTO.issuerName}</dd>
                    
                    <dt><spring:message code="label.validity_start" /></dt>
                    <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${certificateDTO.notBefore}" /></dd>
                    <dt><spring:message code="label.validity_end" /></dt>
                    <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${certificateDTO.notAfter}" /></dd>
                    
                    <dt>SHA-256 (Hex)</dt>
                    <dd>${certificateDTO.sha256Hex}</dd>
                    <dt>SHA-1 (Hex)</dt>
                    <dd>${certificateDTO.sha1Hex}</dd>
                    <dt>SHA-256 (Base64)</dt>
                    <dd>${certificateDTO.sha256Base64}</dd>
                    <dt>SHA-1 (Base64)</dt>
                    <dd>${certificateDTO.sha1Base64}</dd>
                </dl>
            
            </c:if>
        
            <div class="form-group">
                <div class="col-sm-offset-3 col-sm-9">
                    <button type="submit" class="btn btn-primary"><spring:message code="label.submit"/></button>
                </div>
            </div>
        </form:form>
    </div>
</div>

