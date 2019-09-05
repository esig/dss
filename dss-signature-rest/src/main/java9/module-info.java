module jpms_dss_ws_signature_rest {
	
	requires jpms_dss_ws_signature_rest_client;
	requires jpms_dss_ws_signature_remote;
	
	exports eu.europa.esig.dss.ws.signature.rest;
}