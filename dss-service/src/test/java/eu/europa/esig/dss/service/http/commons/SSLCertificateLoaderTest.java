package eu.europa.esig.dss.service.http.commons;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.conn.ssl.TrustStrategy;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class SSLCertificateLoaderTest {
	
	@Test
	public void test() throws Exception {
		String url = "https://dss.nowina.lu/";
		
		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Certificate[] certificates = sslCertificateDataLoader.getCertificates(url);
		assertEquals(2, certificates.length);
		
		List<CertificateToken> certificateTokens = new ArrayList<CertificateToken>();
		for (Certificate certificate : certificates) {
			certificateTokens.add(DSSUtils.loadCertificate(certificate.getEncoded()));
		}
		assertEquals(2, certificateTokens.size());
	}
	
	@Test
	public void noSecureTest() throws Exception {
		String url = "http://dss.nowina.lu/pki-factory/";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Certificate[] certificates = sslCertificateDataLoader.getCertificates(url);
		assertEquals(0, certificates.length);
	}
	
	@Test
	public void tlWebPageTest() throws Exception {
		String url = "https://tsl.belgium.be/tsl-be.xml";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		Certificate[] certificates = sslCertificateDataLoader.getCertificates(url);
		assertEquals(3, certificates.length);
		
		List<CertificateToken> certificateTokens = new ArrayList<CertificateToken>();
		for (Certificate certificate : certificates) {
			certificateTokens.add(DSSUtils.loadCertificate(certificate.getEncoded()));
		}
		assertEquals(3, certificateTokens.size());
	}
	
	@Test
	public void notTrustedHttpsTest() throws Exception {
		String url = "https://tl.nbu.gov.sk/kca/tsl/tsl.xml";

		SSLCertificateLoader sslCertificateDataLoader = new SSLCertificateLoader();
		
		CommonsDataLoader commonsDataLoader = new CommonsDataLoader();
		commonsDataLoader.setTrustStrategy(new TrustStrategy() {
			@Override
			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
				return true;
			}
		});
		
		sslCertificateDataLoader.setCommonsDataLoader(commonsDataLoader);
		
		Certificate[] certificates = sslCertificateDataLoader.getCertificates(url);
		assertEquals(3, certificates.length);
		
		List<CertificateToken> certificateTokens = new ArrayList<CertificateToken>();
		for (Certificate certificate : certificates) {
			certificateTokens.add(DSSUtils.loadCertificate(certificate.getEncoded()));
		}
		assertEquals(3, certificateTokens.size());
	}

}
