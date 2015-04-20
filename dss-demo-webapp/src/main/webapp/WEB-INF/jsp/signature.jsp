<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@taglib uri="http://www.springframework.org/tags" prefix="spring"%>

<h2>
    <spring:message code="label.signature.applet" />
</h2>

<script src="//www.java.com/js/deployJava.js"></script>
<script type="text/javascript">
    var attributes = {
    	width: 800,
    	height :600
    };
    var parameters = {
        service_url : '<c:out value="${prefUrlService.value}"/>',
        default_policy_url : '<c:out value="${prefDefaultPolicyUrl}"/>',
        jnlp_href: 'jnlp/applet.jnlp'
    };
    var version = '1.6';
    deployJava.runApplet(attributes, parameters, version);
</script>

<div class="col-md-8 col-md-offset-2 alert alert-warning" role="alert" id="compatibility_warning" style="display: none;">
    <strong>Warning</strong>
    <p>It seems that your environment does not meet the requirements:</p>
    <ul>
        <li>Java Version: 1.6</li>
        <li>Browser: Internet Explorer (from version 6) or Mozilla Firefox (from version 3.0)</li>
        <li>Architecture: 32 or 64 bit</li>
    </ul>
    <p>We found the following information:</p>
    <p id="compatibility_found"></p>
    <p>Anyway, we tried to start the applet (should be displayed on the top).</p>
</div>

<div class="col-md-8 col-md-offset-2 alert alert-info" role="alert">
    <strong>
        <spring:message code="label.info" />
    </strong>
    <p>For the latest information about DSS compatibility, please consult the pages :</p>
    <ul>
        <li><a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/smartcard-compatibility" class="alert-link">wiki/smartcard-compatibility</a></li>
        <li><a href="https://joinup.ec.europa.eu/software/sd-dss/wiki/applet-compatibility" class="alert-link">wiki/applet-compatibility</a></li>
    </ul>
</div>

<script type="text/javascript">
    function checkRequirements() {
        var version = parseInt(detectBrowserVersion());
        var browser = jQuery.browser;
        
        var compatibleBrowser = false;
        if (browser.msie) {
            if (version >= 6) {
                compatibleBrowser = true;
            }
        } else if (browser.mozilla) {
            if (version >= 3) {
                compatibleBrowser = true;
            }
        }
        var compatibleJava = navigator.javaEnabled();

        if (compatibleBrowser && compatibleJava) {
            return;
        }

        jQuery("#compatibility_found").html(navigator.userAgent);
        jQuery("#compatibility_warning").show("bounce", null, "fast");
    }
    checkRequirements();
</script>
