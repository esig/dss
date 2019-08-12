module jpms_dss_xades {
	
	requires transitive jpms_dss_document;
	
	exports eu.europa.esig.dss.xades;
	exports eu.europa.esig.dss.xades.signature;
	exports eu.europa.esig.dss.xades.validation;
	
    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.xades.validation.XMLDocumentValidatorFactory;
}