module jpms_dss_ws_certificate_validation_common {
	
	requires jpms_dss_common_converter;
	requires jpms_dss_ws_certificate_validation_dto;
	requires jpms_dss_document;
	
	exports eu.europa.esig.dss.ws.cert.validation.common;
}