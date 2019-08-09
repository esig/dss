module jpms_dss_ws_server_signing_rest_client {
	
	requires transitive jpms_dss_ws_server_signing_dto;
	
	exports eu.europa.esig.dss.ws.server.signing.rest.client;
}