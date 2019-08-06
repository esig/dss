module jpms_dss_spi {

	requires transitive jpms_dss_utils;

	exports eu.europa.esig.dss.spi;
	exports eu.europa.esig.dss.spi.client.http;
	exports eu.europa.esig.dss.spi.tsl;
	exports eu.europa.esig.dss.spi.util;
	exports eu.europa.esig.dss.spi.x509;
	exports eu.europa.esig.dss.spi.x509.revocation;
	exports eu.europa.esig.dss.spi.x509.revocation.crl;
	exports eu.europa.esig.dss.spi.x509.revocation.ocsp;
	exports eu.europa.esig.dss.spi.x509.tsp;
}