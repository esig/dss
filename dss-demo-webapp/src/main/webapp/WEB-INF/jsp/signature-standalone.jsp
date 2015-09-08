<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>Standalone application</h2>

<p>
    Download the standalone application <a href="<spring:url value="/downloads/dss-app.zip" />" title="e-signature standalone">(zip)</a> or <a href="<spring:url value="/downloads/dss-app.tar.gz" />" title="e-signature standalone">(tar.gz)</a>
</p>

<div class="panel panel-default">
  <div class="panel-heading" data-toggle="collapse" data-target="#info">
    <h3 class="panel-title">More info...</h3>
  </div>
  <div class="panel-body collapse in" id="info">
    <p>This demo is a standalone application which uses JavaFX (Java 8).</p>
    <p>The application connects directly to the CA's infrastructure to retrieve information such as CRL, OCSP, certificates from AIA ...</p>
    <p>All DSS business logic is embedded inside this application (CAdES, PAdES, XAdES, ASiC). This application doesn't requires a DSS server. </p>
    <div class="col-xs-12 col-md-12">
        <a href="<spring:url value="/images/standalone-application.png"/>" class="thumbnail">
            <img src="<spring:url value="/images/standalone-application.png"/>" alt="Standalone application" class="img-rounded" />
        </a>
    </div>
  </div>
</div>

<script type="text/javascript">
    $('.collapse').collapse();
</script>
