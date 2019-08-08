module jpms_dss_service {
	requires transitive jpms_dss_token;
	requires java.smartcardio;
	
	exports eu.europa.esig.dss.token.mocca;
}