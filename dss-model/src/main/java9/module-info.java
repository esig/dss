module jpms_dss_model {
	requires transitive jpms_dss_enumerations;
	
	exports eu.europa.esig.dss.model;
	exports eu.europa.esig.dss.model.identifier;
	exports eu.europa.esig.dss.model.x509;
}