module jpms_dss_ws_signature_remote {
	
	requires transitive jpms_dss_ws_signature_dto;
	
	exports eu.europa.esig.dss.ws.signature.common;
}