module jpms_dss_asic_xades {

	requires transitive jpms_dss_document;
	requires transitive jpms_dss_asic_common;

	exports eu.europa.esig.dss.asic.xades;
	exports eu.europa.esig.dss.asic.xades.signature;
	exports eu.europa.esig.dss.asic.xades.validation;
}