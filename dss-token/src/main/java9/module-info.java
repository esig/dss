module jpms_dss_token {
	requires jpms_dss_model;
	requires org.slf4j;
	requires jdk.crypto.cryptoki;

	opens jdk.crypto.cryptoki;
	
	exports eu.europa.esig.dss.token;
}