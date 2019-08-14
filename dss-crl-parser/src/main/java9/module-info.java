module jpms_dss_crl_parser {

	requires transitive org.slf4j;
	requires transitive org.bouncycastle.provider;
	
	exports eu.europa.esig.dss.crl;
    uses eu.europa.esig.dss.crl.ICRLUtils;
}