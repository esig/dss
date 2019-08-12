module jpms_dss_policy {
	requires jpms_dss_jaxb_parsers;
	
	exports eu.europa.esig.dss.policy;
	exports eu.europa.esig.dss.policy.jaxb;
}