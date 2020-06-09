module jpms_dss_jades {
	
	requires jpms_dss_document;

	exports eu.europa.esig.dss.jades;
	exports eu.europa.esig.dss.jades.signature;
	exports eu.europa.esig.dss.jades.validation;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
}