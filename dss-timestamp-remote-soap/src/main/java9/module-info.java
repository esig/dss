module jpms_dss_ws_timestamp_remote_soap {
	
	requires jpms_dss_ws_timestamp_remote_soap_client;
	requires jpms_dss_ws_timestamp_remote;
	
	exports eu.europa.esig.dss.ws.timestamp.remote.soap;
}