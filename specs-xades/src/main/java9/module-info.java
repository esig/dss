module jpms_dss_specs_xades {
	requires jpms_dss_jaxb_parsers;
	requires jpms_dss_specs_xmldsig;
	
	exports eu.europa.esig.xades;
	exports eu.europa.esig.xades.jaxb.xades132;
	exports eu.europa.esig.xades.jaxb.xades141;
}