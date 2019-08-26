module jpms_dss_ws_certificate_validation_rest {
	
	requires jpms_dss_ws_certificate_validation_common;
	requires jpms_dss_ws_certificate_validation_rest_client;
	
	exports eu.europa.esig.dss.ws.cert.validation.rest;
}