module jpms_dss_cades {

    requires jpms_dss_document;
	
	exports eu.europa.esig.dss.cades;
	exports eu.europa.esig.dss.cades.signature;
	exports eu.europa.esig.dss.cades.validation;
	exports eu.europa.esig.dss.cades.validation.scope;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.cades.validation.CMSDocumentValidatorFactory;
}