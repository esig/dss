module jpms_dss_ws_server_signing_soap_client {

	requires transitive jpms_dss_ws_server_signing_dto;
	
	exports eu.europa.esig.dss.ws.server.signing.soap.client;
}