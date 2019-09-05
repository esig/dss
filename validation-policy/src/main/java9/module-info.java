module jpms_dss_validation_policy {
	requires transitive org.slf4j;
	
	exports eu.europa.esig.dss.validation.executor;
	exports eu.europa.esig.dss.validation.reports;
	
}