module jpms_dss_ws_server_signing_soap {

	requires jpms_dss_ws_server_signing_common;
	requires jpms_dss_ws_server_signing_soap_client;
	
	exports eu.europa.esig.dss.ws.server.signing.soap;
}