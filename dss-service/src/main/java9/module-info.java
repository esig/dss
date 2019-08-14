module jpms_dss_service {
	requires java.sql;
	requires transitive jpms_dss_spi;
	requires org.apache.httpcomponents.httpclient;
	
	exports eu.europa.esig.dss.service;
	exports eu.europa.esig.dss.service.crl;
	exports eu.europa.esig.dss.service.http.commons;
	exports eu.europa.esig.dss.service.http.proxy;
	exports eu.europa.esig.dss.service.ocsp;
	exports eu.europa.esig.dss.service.tsp;
}