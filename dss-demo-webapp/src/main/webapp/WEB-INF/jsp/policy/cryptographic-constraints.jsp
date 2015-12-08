<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#block-<c:out value="${param.id}"/>">
        <h3 class="panel-title">
            <spring:message code="label.policy.cryptographic" />
        </h3>
    </div>
    <div class="panel-body collapse in cryptographic-block" id="block-<c:out value="${param.id}" />">

        <div class="form-group encryptionAlgos" >
            <label class="col-sm-5 control-label"><spring:message code="label.policy.acceptableEncryptionAlgo" /></label>
            <div class="col-sm-7">
                <c:forEach var="supportedAlgo" items="${supportedEncryptionAlgos}" varStatus="loop">
                    <c:set var="checked" value="" />
                    <c:forEach var="algo" items="${cryptographic.acceptableEncryptionAlgo.algo}">
                        <c:if test="${algo.value == supportedAlgo}">
                            <c:set var="checked" value="checked" />
                        </c:if>
                    </c:forEach>
                    <input name="encryptionAlgo" type="checkbox" id="encryptionAlgo-<c:out value="${param.pathToBind}"/>-<c:out value="${supportedAlgo}"/>" class="encryptionAlgo" value="<c:out value="${supportedAlgo}"/>" <c:if test="${not empty checked}"> checked="checked"</c:if> /> <c:out value="${supportedAlgo}"/> <br />
                </c:forEach>
            </div>
        </div>

        <div class="form-group encryptionAlgoSizes">
            <label class="col-sm-5 control-label"><spring:message code="label.policy.miniPublicKeySize" /></label>
            <div class="col-sm-7" id="encryptionAlgoSizes-<c:out value="${param.pathToBind}" />">
                <c:forEach var="algo" items="${cryptographic.miniPublicKeySize.algo}">
                    <div class="form-group" id="encryptionAlgoSize-<c:out value="${param.pathToBind}"/>-<c:out value="${algo.value}"/>">
                        <label class="col-sm-2 control-label"><c:out value="${algo.value}" /></label>
                        <div class="col-sm-4">
                            <input type="text" id="encryptionAlgoSize-<c:out value="${param.pathToBind}"/>-<c:out value="${algo.value}"/>" name="<c:out value="${algo.value}"/>" value="<c:out value="${algo.size}"/>" class="form-control" />
                        </div>
                    </div>
                </c:forEach>
            </div>
        </div>

        <div class="form-group digestAlgos">
            <label class="col-sm-5 control-label"><spring:message code="label.policy.acceptableDigestAlgo" /></label>
            <div class="col-sm-7">
                <c:forEach var="supportedAlgo" items="${supportedDigestAlgos}" varStatus="loop">
                    <c:set var="checked" value="" />
                    <c:forEach var="algo" items="${cryptographic.acceptableDigestAlgo.algo}">
                        <c:if test="${algo.value == supportedAlgo}">
                            <c:set var="checked" value="checked" />
                        </c:if>
                    </c:forEach>
                    <input name="digestAlgo" type="checkbox" id="digestAlgo-<c:out value="${param.pathToBind}"/>-<c:out value="${supportedAlgo}"/>"  value="<c:out value="${supportedAlgo}"/>" <c:if test="${not empty checked}"> checked="checked"</c:if> /> <c:out value="${supportedAlgo}"/> <br />
                </c:forEach>
            </div>
        </div>
        
        <div id="hiddenCryptoFields-<c:out value="${param.pathToBind}"/>">
        
        </div>

    </div>
</div>    
<c:remove var="cryptographic"/>
