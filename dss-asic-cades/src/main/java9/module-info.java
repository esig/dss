module jpms_dss_asic_cades {
	
	requires transitive jpms_dss_document;
	requires transitive jpms_dss_asic_common;
	requires transitive jpms_dss_cades;

	exports eu.europa.esig.dss.asic.cades;
	exports eu.europa.esig.dss.asic.cades.signature;
	exports eu.europa.esig.dss.asic.cades.validation;
	
    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.asic.cades.validation.ASiCContainerWithCAdESValidatorFactory;
}