module jpms_dss_specs_trusted_list {
	requires jpms_dss_jaxb_parsers;
	requires jpms_dss_specs_xmldsig;
	requires jpms_dss_specs_xades;
	
	exports eu.europa.esig.trustedlist;
	exports eu.europa.esig.trustedlist.enums;
	exports eu.europa.esig.trustedlist.jaxb.ecc;
	exports eu.europa.esig.trustedlist.jaxb.tsl;
	exports eu.europa.esig.trustedlist.jaxb.tslx;
}