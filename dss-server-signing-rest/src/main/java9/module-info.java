module jpms_dss_ws_server_signing_rest {
	
	requires jpms_dss_ws_server_signing_common;
	requires jpms_dss_ws_server_signing_rest_client;
	
	exports eu.europa.esig.dss.ws.server.signing.rest;
}