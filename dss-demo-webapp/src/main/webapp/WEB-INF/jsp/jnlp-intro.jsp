<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>JNLP + SOAP WebServices</h2>

<p>
    Download the <a href="<spring:url value="/dss-signature.jnlp" />" title="e-signature jnlp">JNLP file</a>
    <a href="<spring:url value="/dss-signature.jnlp" />" title="e-signature jnlp"><img alt="JNLP File" src="<spring:url value="/images/jnlp-icon.png" />" /></a>
</p>

<div class="panel panel-default">
  <div class="panel-heading" data-toggle="collapse" data-target="#info">
    <h3 class="panel-title">More info...</h3>
  </div>
  <div class="panel-body collapse in" id="info">
    <p>This demo uses a JNLP file (to be executed with Java Web Start) and a <a href="<spring:url value="/services/SignatureService?wsdl" />" title="eSignature SOAP webservices">SOAP WebServices</a>.</p>
    <p>The application (Swing technology) allows to set parameters of the signature and interacts with the DSS server (SOAP) and SSCD.</p>
    <p>DSS server offers SOAP and REST WebServices.</p>
    <p>DSS business logic is embedded on the server side (CAdES, PAdES, XAdES, ASiC).</p>
    <div class="col-xs-12 col-md-12">
        <a href="<spring:url value="/images/jnlp-webservices.png"/>" class="thumbnail">
            <img src="<spring:url value="/images/jnlp-webservices.png"/>" alt="JNLP with webservices" class="img-rounded" />
        </a>
    </div>
  </div>
</div>

<script type="text/javascript">
    $('.collapse').collapse();
</script>
