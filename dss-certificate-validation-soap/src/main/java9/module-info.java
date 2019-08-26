module jpms_dss_ws_certificate_validation_soap {
	requires jpms_dss_ws_certificate_validation_common;
	requires jpms_dss_ws_certificate_validation_soap_client;
	
	exports eu.europa.esig.dss.ws.cert.validation.soap;
}