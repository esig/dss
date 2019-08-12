module jpms_dss_ws_server_signing_dto {

	requires transitive jpms_dss_common_remote_dto;
	
	exports eu.europa.esig.dss.ws.server.signing.dto;
}