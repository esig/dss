<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<div class="panel panel-default">
    <div class="panel-heading" data-toggle="collapse" data-target="#block-${param.id}">
        <h3 class="panel-title">
            <spring:message code="label.policy.cryptographic" />
        </h3>
    </div>
    <div class="panel-body collapse in cryptographic-block" id="block-${param.id}">

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
                    <input name="encryptionAlgo" type="checkbox" id="encryptionAlgo-${param.pathToBind}-${supportedAlgo}" class="encryptionAlgo" value="${supportedAlgo}" <c:if test="${not empty checked}"> checked="checked"</c:if> /> ${supportedAlgo} <br />
                </c:forEach>
            </div>
        </div>

        <div class="form-group encryptionAlgoSizes">
            <label class="col-sm-5 control-label"><spring:message code="label.policy.miniPublicKeySize" /></label>
            <div class="col-sm-7" id="encryptionAlgoSizes-${param.pathToBind}">
                <c:forEach var="algo" items="${cryptographic.miniPublicKeySize.algo}">
                    <div class="form-group" id="encryptionAlgoSize-${param.pathToBind}-${algo.value}">
                        <label class="col-sm-2 control-label">${algo.value}</label>
                        <div class="col-sm-4">
                            <input type="text" id="encryptionAlgoSize-${param.pathToBind}-${algo.value}" name="${algo.value}" value="${algo.size}" class="form-control" />
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
                    <input name="digestAlgo" type="checkbox" id="digestAlgo-${param.pathToBind}-${supportedAlgo}"  value="${supportedAlgo}" <c:if test="${not empty checked}"> checked="checked"</c:if> /> ${supportedAlgo} <br />
                </c:forEach>
            </div>
        </div>
        
        <div id="hiddenCryptoFields-${param.pathToBind}">
        
        </div>

    </div>
</div>    
<c:remove var="cryptographic"/>
