module jpms_dss_validation_policy {
	requires org.slf4j;

	exports eu.europa.esig.dss.validation.executor;
	exports eu.europa.esig.dss.validation.executor.certificate;
	exports eu.europa.esig.dss.validation.executor.signature;
	exports eu.europa.esig.dss.validation.reports;
	
}