<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>


<h2>
    <spring:message code="label.tsl" />
</h2>

<c:choose>
	<c:when test="${model == null}">
		No info found for country "<c:out value="${country}"/>"
	
	</c:when>
	<c:otherwise>
		
		<jsp:useBean id="now" class="java.util.Date"/>
		
		<c:set var="countryCode" value="${country}" />
		
		<c:set var="panelStyle" value="" />
		<c:choose>
		    <c:when test="${model.validationResult != null && model.validationResult.invalid}">
		        <c:set var="panelStyle" value="panel-danger" />
		    </c:when>
		    <c:when test="${(model.parseResult != null && model.parseResult.nextUpdateDate != null && model.parseResult.nextUpdateDate le now) || (model.validationResult != null && model.validationResult.indeterminate)}">
		        <c:set var="panelStyle" value="panel-warning" />
		    </c:when>
		    <c:when test="${model.validationResult != null && model.validationResult.valid}">
		        <c:set var="panelStyle" value="panel-success" />
		    </c:when>
		</c:choose>
		
		
		<div class="panel ${panelStyle}">
		    <div class="panel-heading clearfix">
			    <div class="pull-right">
					<select class="form-control" id="countrySelector">
						<option>Select another country</option>
						<c:forEach var="c" items="${countries}">
							<c:if test="${country != c}">
								<option value="${fn:toLowerCase(c)}">${c}</option>
							</c:if>
						</c:forEach>
					</select>
				</div>
		        <h3 class="panel-title" style="padding-top: 7.5px;"><c:out value="${countryCode}" /></h3>
		    </div>
		    <div class="panel-body">
		        <dl class="dl-horizontal">
		            <dt>Url : </dt>
		            <dd><a href="<c:out value="${model.url}" />"><c:out value="${model.url}"/></a></dd>
		
		            <c:if test="${model.loadedDate !=null}">
		                <dt>Check date : </dt>
		                <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${model.loadedDate}" /></dd>
		            </c:if>
		            
		            <c:if test="${model.validationResult != null}">
		                <dt>Indication : </dt>
		                <dd>
		                    <c:choose>
		                        <c:when test="${model.validationResult.valid}">
		                            <span class="glyphicon glyphicon-ok-sign text-success"></span>
		                        </c:when>
		                        <c:when test="${model.validationResult.indeterminate}">
		                            <span class="glyphicon glyphicon-question-sign text-warning"></span>
		                        </c:when>
		                        <c:otherwise>
		                            <span class="glyphicon glyphicon-remove-sign text-danger"></span>
		                        </c:otherwise>
		                    </c:choose>
		                    <c:out value="${model.validationResult.indication}"/>
		                </dd>
		                <c:if test="${not empty model.validationResult.subIndication}">
		                    <dt>Sub indication : </dt>
		                    <dd><c:out value="${model.validationResult.subIndication}" /></dd>
		                </c:if>
		            </c:if>
		            
		            <c:if test="${model.parseResult !=null}">
		                <dt>Sequence number :</dt>
		                <dd><c:out value="${model.parseResult.sequenceNumber}"/></dd>
		                <dt>Issue date : </dt>
		                <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${model.parseResult.issueDate}" /></dd>
		                <dt>Next update date : </dt>
		                <dd${model.parseResult.nextUpdateDate le now ? ' style="color:red"' : ''}><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${model.parseResult.nextUpdateDate}" /></dd>
		            </c:if>
		        </dl>
		        
		        <c:if test="${model.parseResult !=null && not empty model.parseResult.serviceProviders}">
		            <div class="panel panel-default">
		                <div class="panel-heading">
		                    <span class="badge pull-right">${fn:length(model.parseResult.serviceProviders)}</span>
		                    <h3 class="panel-title">Trust service providers</h3>
		                </div>
		                <div class="panel-body">
		                    <c:forEach var="serviceProvider" items="${model.parseResult.serviceProviders}" varStatus="sp">
		                        <dl class="dl-horizontal">
		                            <dt>Name :</dt>
		                            <dd><c:out value="${serviceProvider.name} "/></dd>
		                            <c:if test="${not empty serviceProvider.tradeName}">
		                                <dt>Trade name :</dt>
		                                <dd><c:out value="${serviceProvider.tradeName} "/></dd>
		                            </c:if>
		                            <dt>Postal address :</dt>
		                            <dd><c:out value="${serviceProvider.postalAddress}" /></dd>
		                            <dt>Electronic address :</dt>
		                            <dd><a href="<c:out value="${serviceProvider.electronicAddress}"/>" title="<c:out value="${serviceProvider.name}"/>"><c:out value="${serviceProvider.electronicAddress}" /></a></dd>
		                        </dl>
		                        <c:if test="${not empty serviceProvider.services}">
		                            <div class="panel panel-default">
		                                <div class="panel-heading" data-toggle="collapse" data-target="#countryServices${countryCode}${sp.index}">
		                                    <span class="badge pull-right">${fn:length(serviceProvider.services)}</span>
		                                    <h3 class="panel-title">Trust services</h3>
		                                </div>
		                                <div class="panel-body collapse in" id="countryServices${countryCode}${sp.index}">
		                                    <c:forEach var="service" items="${serviceProvider.services}" varStatus="ser">
		                                        <dl class="dl-horizontal">
		                                            <dt>Name :</dt>
		                                            <dd><c:out value="${service.name}"/></dd>
		                                            <dt>Status :</dt>
		                                            <dd><a href="<c:out value="${service.status}" />"><c:out value="${service.status}"/></a></dd>
		                                            <dt>Type :</dt>
		                                            <dd><a href="<c:out value="${service.type}" />"><c:out value="${service.type}" /></a></dd>
		                                            <dt>Start date :</dt>
		                                            <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${service.startDate}" /></dd>
		                                            <c:if test="${service.endDate !=null}">
		                                                <dt>End date :</dt>
		                                                <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${service.endDate}" /></dd>
		                                            </c:if>
		                                        </dl>
		                                        
		                                        <c:if test="${not empty service.certificates}">
		                                            <div class="panel panel-default">
		                                                <div class="panel-heading" data-toggle="collapse" data-target="#countryCertificates${countryCode}${sp.index}-${ser.index}">
		                                                    <span class="badge pull-right">${fn:length(service.certificates)}</span>
		                                                    <h3 class="panel-title">Certificates</h3>
		                                                </div>
		                                                <div class="panel-body collapse in" id="countryCertificates${countryCode}${sp.index}-${ser.index}">
		                                                    <c:forEach var="token" items="${service.certificates}">
		                                                        <dl class="dl-horizontal">
		                                                            <dt><spring:message code="label.service" /> :</dt>
		                                                            <dd><c:out value="${token.certificate.subjectDN.name}" /></dd>
		                                                            <dt><spring:message code="label.issuer" /> :</dt>
		                                                            <dd><c:out value="${token.certificate.issuerDN.name}" /></dd>
		                                                            <dt>Serial number</dt>
		                                                            <dd><c:out value="${token.serialNumber}" /></dd>
		                                                            <dt><spring:message code="label.validity_start" /></dt>
		                                                            <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${token.certificate.notBefore}" /></dd>
		                                                            <dt><spring:message code="label.validity_end" /></dt>
		                                                            <dd><fmt:formatDate pattern="dd/MM/yyyy HH:mm:ss" value="${token.certificate.notAfter}" /></dd>
		                                                        </dl>
		                                                    </c:forEach>
		                                                </div>
		                                            </div>
		                                        </c:if>
		                                        
		                                        <c:if test="${not empty service.x500Principals}">
		                                            <div class="panel panel-default">
		                                                <div class="panel-heading" data-toggle="collapse" data-target="#countryx500Principals${countryCode}${sp.index}-${ser.index}">
		                                                    <span class="badge pull-right">${fn:length(service.x500Principals)}</span>
		                                                    <h3 class="panel-title">X509 Subject Names</h3>
		                                                </div>
		                                                <div class="panel-body collapse in" id="countryx500Principals${countryCode}${sp.index}-${ser.index}">
		                                                    <c:forEach var="x500" items="${service.x500Principals}">
		                                                        <dl class="dl-horizontal">
		                                                            <dt><spring:message code="label.service" /> :</dt>
		                                                            <dd><c:out value="${x500.name}" /></dd>
		                                                        </dl>
		                                                    </c:forEach>
		                                                </div>
		                                            </div>
		                                        </c:if>
		                                    </c:forEach>
		                                </div>
		                            </div>
		                        </c:if>
		                    </c:forEach>
		                </div>
		            </div>
		        </c:if>
		        
		        <c:if test="${model.parseResult !=null && not empty model.parseResult.pointers}">
		             <div class="panel panel-default">
		                <div class="panel-heading">
		                <span class="badge pull-right">${fn:length(model.parseResult.pointers)}</span>
		                    <h3 class="panel-title">Machine processable pointers</h3>
		                </div>
		                <div class="panel-body">
		                    <ul>
		                        <c:forEach var="item" items="${model.parseResult.pointers}">
		                            <li><a href="<c:out value="${item.url}" />"><c:out value="${item.url}" /></a></li>
		                        </c:forEach>
		                    </ul>
		                </div>
		            </div>
		        </c:if>
		    </div>
		</div>
	</c:otherwise>
</c:choose>	

<script type="text/javascript">
	$('.collapse').collapse();
	
	$('#countrySelector').change(function() {
		  window.location = '<spring:url value="/tsl-info/"/>'+$(this).val();
	});
</script>
