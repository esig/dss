module jpms_dss_ws_signature_soap {
	
	requires jpms_dss_ws_signature_remote;
	requires jpms_dss_ws_signature_soap_client;
	
	exports eu.europa.esig.dss.ws.signature.soap;
}