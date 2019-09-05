module jpms_dss_ws_signature_rest_client {
	
	requires transitive jpms_dss_ws_signature_dto;
	
	exports eu.europa.esig.dss.ws.signature.rest.client;
}