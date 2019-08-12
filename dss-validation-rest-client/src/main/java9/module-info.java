module jpms_dss_ws_validation_rest_client {
	
	requires transitive jpms_dss_ws_validation_dto;
	
	exports eu.europa.esig.dss.ws.validation.rest.client;
}