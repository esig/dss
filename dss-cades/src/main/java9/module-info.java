module jpms_dss_cades {

	requires transitive jpms_dss_document;
	
	exports eu.europa.esig.dss.cades;
	exports eu.europa.esig.dss.cades.signature;
	exports eu.europa.esig.dss.cades.validation;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.cades.validation.CMSDocumentValidatorFactory;
}