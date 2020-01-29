module jpms_dss_ws_timestamp_remote_rest_client {
	
	requires transitive jpms_dss_ws_timestamp_dto;
	
	exports eu.europa.esig.dss.ws.timestamp.remote.rest.client;
}