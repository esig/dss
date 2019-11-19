module jpms_dss_asic_xades {

	requires transitive jpms_dss_document;
	requires transitive jpms_dss_asic_common;
	requires transitive jpms_dss_xades;

	exports eu.europa.esig.dss.asic.xades;
	exports eu.europa.esig.dss.asic.xades.definition;
	exports eu.europa.esig.dss.asic.xades.signature;
	exports eu.europa.esig.dss.asic.xades.validation;

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory;
}