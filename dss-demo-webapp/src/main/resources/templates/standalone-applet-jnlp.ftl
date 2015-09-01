<?xml version="1.0" encoding="utf-8"?>
<jnlp spec="1.0+" href="standalone-applet.jnlp">
	<information>
		<title>DSS Demo Application</title>
		<vendor>Nowina Solutions toto</vendor>
		<offline-allowed />
	</information>
	<security>
		<all-permissions/>
	</security>
	<resources>
		<j2se version="1.6+" href="http://java.sun.com/products/autodl/j2se" />
		<jar href="${jarUrl}" main="true" />
	</resources>
	<applet-desc name="Signature Demo Applet" main-class="eu.europa.esig.dss.applet.main.DSSAppletCore" 
		width="800"
		height="600">
	
		<param name="service_url" value="${(urlServiceValue)!''}"/>
		<param name="default_policy_url" value="${(defaultPolicyUrlValue)!''}"/>
		
	</applet-desc>
</jnlp>