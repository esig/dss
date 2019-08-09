module jpms_dss_ws_signature_soap_client {

	requires transitive jpms_dss_ws_signature_dto;
	
	exports eu.europa.esig.dss.ws.signature.soap.client;
}