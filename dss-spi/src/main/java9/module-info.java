module jpms_dss_spi {

	requires jpms_dss_utils;

	requires org.slf4j;
	requires org.bouncycastle.provider;
	requires org.bouncycastle.pkix;
	
	exports eu.europa.esig.dss.spi;
	exports eu.europa.esig.dss.spi.client.http;
	exports eu.europa.esig.dss.spi.exception;
	exports eu.europa.esig.dss.spi.tsl;
	exports eu.europa.esig.dss.spi.util;
	exports eu.europa.esig.dss.spi.x509;
	exports eu.europa.esig.dss.spi.x509.revocation;
	exports eu.europa.esig.dss.spi.x509.revocation.crl;
	exports eu.europa.esig.dss.spi.x509.revocation.ocsp;
	exports eu.europa.esig.dss.spi.x509.tsp;
}