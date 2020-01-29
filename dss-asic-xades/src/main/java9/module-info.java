module jpms_dss_asic_xades {
	
    requires jpms_dss_document;

	exports eu.europa.esig.dss.asic.xades;
	exports eu.europa.esig.dss.asic.xades.definition;
	exports eu.europa.esig.dss.asic.xades.signature;
	exports eu.europa.esig.dss.asic.xades.signature.asice;
	exports eu.europa.esig.dss.asic.xades.signature.asics;
	exports eu.europa.esig.dss.asic.xades.validation;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
}