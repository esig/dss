module jpms_dss_common_converter {
	
	requires transitive jpms_dss_common_remote_dto;
	
	exports eu.europa.esig.dss.ws.converter;
}