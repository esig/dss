module jpms_dss_specs_validation_report {
	requires jpms_dss_jaxb_parsers;
	requires jpms_dss_specs_xmldsig;
	requires jpms_dss_specs_xades;
	requires jpms_dss_specs_trusted_list;
	
	exports eu.europa.esig.validationreport;
	exports eu.europa.esig.validationreport.enums;
	exports eu.europa.esig.validationreport.jaxb;
}