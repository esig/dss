module jpms_dss_token {
	requires transitive jpms_dss_model;
	requires jdk.crypto.cryptoki;
	opens jdk.crypto.cryptoki;
	
	exports eu.europa.esig.dss.token;
}