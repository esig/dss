module jpms_dss_model {
	requires transitive jpms_dss_enumerations;
	
	exports eu.europa.esig.dss;
	exports eu.europa.esig.dss.identifier;
	exports eu.europa.esig.dss.x509;
}