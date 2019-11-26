module jpms_dss_ws_timestamp_remote_rest {
	
	requires jpms_dss_ws_timestamp_remote_rest_client;
	requires jpms_dss_ws_timestamp_remote;
	
	exports eu.europa.esig.dss.ws.timestamp.remote.rest;
}