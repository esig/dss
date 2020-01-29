module jpms_dss_asic_cades {
	
    requires jpms_dss_document;
	
	exports eu.europa.esig.dss.asic.cades;
	exports eu.europa.esig.dss.asic.cades.signature;
	exports eu.europa.esig.dss.asic.cades.signature.asice;
	exports eu.europa.esig.dss.asic.cades.signature.asics;
	exports eu.europa.esig.dss.asic.cades.signature.manifest;
	exports eu.europa.esig.dss.asic.cades.validation;
	exports eu.europa.esig.dss.asic.cades.validation.scope;
	
    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
}