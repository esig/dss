module jpms_dss_specs_saml_assertion {
	requires jpms_dss_jaxb_parsers;
	requires jpms_dss_specs_xmldsig;
	
	exports eu.europa.esig.saml;
	exports eu.europa.esig.saml.jaxb.assertion;
	exports eu.europa.esig.saml.jaxb.assertion.runtime;
	exports eu.europa.esig.saml.jaxb.authn.context;
	exports eu.europa.esig.saml.jaxb.dce;
	exports eu.europa.esig.saml.jaxb.ecp;
	exports eu.europa.esig.saml.jaxb.protocol;
	exports eu.europa.esig.soap.jaxb.envelope;
	exports eu.europa.esig.xmlenc.jaxb;
}