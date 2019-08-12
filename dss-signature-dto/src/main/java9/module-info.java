module jpms_dss_ws_signature_dto {
	
	requires transitive jpms_dss_common_remote_dto;
	
	exports eu.europa.esig.dss.ws.signature.dto;
	exports eu.europa.esig.dss.ws.signature.dto.parameters;
}