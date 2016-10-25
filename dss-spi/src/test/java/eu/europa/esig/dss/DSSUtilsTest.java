package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public class DSSUtilsTest {

	private static final Logger logger = LoggerFactory.getLogger(DSSUtilsTest.class);

	private static CertificateToken certificateWithAIA;

	@BeforeClass
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void testLoadIssuer() {
		CertificateToken issuer = DSSUtils.loadIssuerCertificate(certificateWithAIA, new NativeHTTPDataLoader());
		assertNotNull(issuer);
		assertTrue(certificateWithAIA.isSignedBy(issuer));
	}

	@Test
	public void testLoadIssuerEmptyDataLoader() {
		assertNull(DSSUtils.loadIssuerCertificate(certificateWithAIA, null));
	}

	@Test
	public void testLoadIssuerNoAIA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		assertNull(DSSUtils.loadIssuerCertificate(certificate, new NativeHTTPDataLoader()));
	}

	@Test
	public void loadCertificate() throws Exception {
		CertificateToken certificate = DSSUtils.loadCertificate(new FileInputStream("src/test/resources/belgiumrs2.crt"));
		assertNotNull(certificate);

		FileInputStream fis = new FileInputStream("src/test/resources/belgiumrs2.crt");
		byte[] byteArray = Utils.toByteArray(fis);
		logger.info(Utils.toBase64(byteArray));
		Utils.closeQuietly(fis);
		CertificateToken certificate2 = DSSUtils.loadCertificate(byteArray);
		assertNotNull(certificate2);

		CertificateToken certificateNew = DSSUtils.loadCertificate(new FileInputStream("src/test/resources/belgiumrs2-new.crt"));
		assertNotNull(certificateNew);

		FileInputStream fisNew = new FileInputStream("src/test/resources/belgiumrs2-new.crt");
		byte[] byteArrayNew = Utils.toByteArray(fisNew);
		logger.info(Utils.toBase64(byteArrayNew));
		Utils.closeQuietly(fisNew);
		CertificateToken certificate2New = DSSUtils.loadCertificate(byteArrayNew);
		assertNotNull(certificate2New);

		// String cert =
		// "PGh0bWw+PGhlYWQ+PHRpdGxlPlJlcXVlc3QgUmVqZWN0ZWQ8L3RpdGxlPjwvaGVhZD48Ym9keT5UaGUgcmVxdWVzdGVkIFVSTCB3YXMgcmVqZWN0ZWQuIFBsZWFzZSBjb25zdWx0IHdpdGggeW91ciBhZG1pbmlzdHJhdG9yLjxicj48YnI+WW91ciBzdXBwb3J0IElEIGlzOiAxMTY1Njg3NjQzMzgzMDI3NjMxNjwvYm9keT48L2h0bWw+";
		// byte[] decodeBase64 = Base64.decodeBase64(cert);
		// byte[] decodeBase642 = Base64.decodeBase64(decodeBase64);
		// CertificateToken certificate3 =
		// DSSUtils.loadCertificate(base64StringToBase64Binary);
		// assertNotNull(certificate3);
	}

	@Test(expected = DSSException.class)
	public void loadCertificateDoesNotThrowNullPointerExceptionWhenProvidedNonCertificateFile() throws Exception {
		DSSUtils.loadCertificate(new ByteArrayInputStream("test".getBytes("UTF-8")));
	}

	@Test
	public void convertToPEM() {
		String convertToPEM = DSSUtils.convertToPEM(certificateWithAIA);
		assertTrue(convertToPEM.contains(DSSUtils.CERT_BEGIN));
		assertTrue(convertToPEM.contains(DSSUtils.CERT_END));

		assertTrue(DSSUtils.isPEM(new ByteArrayInputStream(convertToPEM.getBytes())));

		CertificateToken certificate = DSSUtils.loadCertificate(convertToPEM.getBytes());
		assertEquals(certificate,certificateWithAIA);

		byte[] certDER = DSSUtils.convertToDER(convertToPEM);
		assertFalse(DSSUtils.isPEM(new ByteArrayInputStream(certDER)));

		CertificateToken certificate2 = DSSUtils.loadCertificate(certDER);
		assertEquals(certificate2,certificateWithAIA);
	}

	@Test
	public void loadCrl() throws Exception {
		X509CRL crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/belgium2.crl"));
		assertNotNull(crl);
		assertFalse(DSSUtils.isPEM(new FileInputStream("src/test/resources/crl/belgium2.crl")));

		String convertCRLToPEM = DSSUtils.convertCrlToPEM(crl);
		assertTrue(DSSUtils.isPEM(new ByteArrayInputStream(convertCRLToPEM.getBytes())));
		assertTrue(DSSUtils.isPEM(convertCRLToPEM.getBytes()));

		X509CRL crl2 = DSSUtils.loadCRL(convertCRLToPEM.getBytes());
		assertEquals(crl, crl2);

		byte[] convertCRLToDER = DSSUtils.convertCRLToDER(convertCRLToPEM);
		X509CRL crl3 = DSSUtils.loadCRL(convertCRLToDER);
		assertEquals(crl, crl3);
	}

	@Test
	public void loadPEMCrl() throws Exception {
		X509CRL crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/LTRCA.crl"));
		assertNotNull(crl);
		assertTrue(DSSUtils.isPEM(new FileInputStream("src/test/resources/crl/LTRCA.crl")));
	}

	@Test
	public void testChainFromSchemeServiceDefinitionURI() {

		String base64 = "MIIFvjCCA6agAwIBAgIQALwvYx2O1YN6UxQOi3Bx3jANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJFUzEoMCYGA1UECgwfRElSRUNDSU9OIEdFTkVSQUwgREUgTEEgUE9MSUNJQTEMMAoGA1UECwwDQ05QMRQwEgYDVQQDDAtBQyBSQUlaIERHUDAeFw0wNzAxMjUxMjA1MDhaFw0zNzAxMjUxMjA1MDhaMFsxCzAJBgNVBAYTAkVTMSgwJgYDVQQKDB9ESVJFQ0NJT04gR0VORVJBTCBERSBMQSBQT0xJQ0lBMQwwCgYDVQQLDANDTlAxFDASBgNVBAMMC0FDIFJBSVogREdQMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAgBD1t16zMJxvoxuIDlyt6pfgzPmmfJMFvPyoj0AOxjyxu6f77K/thV/pMatQqjGae3Yj83upv7YFygq/jU02EeEIeQQEf+QJ+B+LX+oGLPbU5g8/W1eFcnXC4Jg2ipP7L2qcEfA180AsT1UqmHTc7kRI3N6yJZZiHkM4hpjf3vgsCxUQtXw+XAZYtaRbjFO69tTSdbpbXN4fvOQwHNlenF1GMxsih7tgGUwRlY2EVfh7EGYvXt2mtpHiEIeSp1s2WBxzgiWU1IufiDo18olZj859oHkNBD0sx6LVPPun/sINuM1M6aBRwc725cMgZmIyNDOHZkqExL8DNUiTzXYzqr7R/X+kn59RYLwIEmfRQLkKxyYlZeFbuOI5n7Uz3vKANcTbUuCymA0+ZA9ESlrz8kA6fHV0+fMePUBYnociJO5fFX/jxtScOqrQt+K+gGm4TubalBoL7ECGzs3CmKtnuyOH+KFO/8q71Fxhn3WqlKgO7dBUhp0I/7dr4R2bF4ry1NnqZWObCuBfKqyL80Dx+6zaGsTo7UBLNdcA4sXArJoAMUqHb/77rqu45dWJIhQA5V3qolwowwuTdZwC1ec2AWwA6gMf2uchNJsPWWmQrkXvkhu2rI756cKwgR7y22517q/B9MNx7InsZbMbOWUwQuei3UcoIgCFs2TWCbhxHNkCAwEAAaN+MHwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFA6cduGiLokzQfLjPmxbFkW9vYaOMDoGA1UdIAQzMDEwLwYEVR0gADAnMCUGCCsGAQUFBwIBFhlodHRwOi8vd3d3LnBvbGljaWEuZXMvZHBjMA0GCSqGSIb3DQEBBQUAA4ICAQBslvw3pwCj21vCctyL7YOrmfINjJFp4TNFfNnDwSsuonqOjwppXCEFJ6MkOeCUOy9vXziNoYtoDd/tXAn++9975d7PB9vXnu7ErHRx+e74obKpqfBoVv9fwPp0bObO3YbTq9EGPLM8mbcUEivPlL2mQ7tk78z2p8gpytcCZRc08Jd5m+AeYPrHUDeF6ZIlnH7SIrtP3Bp8zwnNIFbNtkyrCyWtN8Ajo3RXqecM/bs+YgGzjVbDToQUBkBCuoG3XU+QYSQ79yZsvjTCsFKBYnXXijiGZSokx33iauY0PIyaNu/ulMloSNUwWZ5WBPqJXWlkZ+deApxZLXJLFMSTjFeFdpZUgOC1wrRkxXidWQwr4566fYWhYH0w+hwK9gD6NEsMA3D7NOPCTCOx9Qst5848RsJVJ4F+ZFmT4iyTYLyglkNkeB+tSXVyC9Lg+Tvay85VyeZMSZ3PpGmpNzaQxVZl9XCfs8R6Ew4pG91eOA0BjsI1ZHY7H9e5Pomup/jTA6JwlCYooEiBM31Gdwe/3oUFNzB+NvOWdwb+ZG6va70j98EdipGWoLvjv/oJlFN2q1Nrt/u7whKp+VsVOjuZMrSpw9C+Ec4yiLha5RRiXnHX1cqwT694KIDQZIgqQChQDeDqrvCphtdHdxFQ5NBzt2HKhaSh8ggDdOdpH451rB45Jg==";
		CertificateToken issuerCert = DSSUtils.loadCertificateFromBase64EncodedString(base64);
		assertNotNull(issuerCert);
		assertTrue(issuerCert.isSelfSigned());

		CertificateToken childCert = DSSUtils.loadCertificate(new File("src/test/resources/es_certificate_from_SchemeServiceDefinitionURI.crt"));
		assertNotNull(childCert);
		assertFalse(childCert.isSelfSigned());
		assertTrue(childCert.isSignedBy(issuerCert));

		CertificateToken childCert2 = DSSUtils.loadCertificate(new File("src/test/resources/es_certificate_from_SchemeServiceDefinitionURI2.crt"));
		assertNotNull(childCert2);
		assertFalse(childCert2.isSelfSigned());
		assertTrue(childCert2.isSignedBy(issuerCert));
	}

	@Test
	public void loadRootCA2NotSelfSign() throws Exception {

		String certBase64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";
		CertificateToken rootCA2 = DSSUtils.loadCertificateFromBase64EncodedString(certBase64);
		logger.info(rootCA2.toString());
		logger.info(rootCA2.getCertificate().toString());
		// assertFalse(rootCA2.isSelfSigned());

		X509Certificate certificate = rootCA2.getCertificate();
		certificate.verify(certificate.getPublicKey());
	}

	@Test
	public void testRootCA2s() {

		CertificateToken selfSign = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrca2-self-sign.crt"));
		CertificateToken signed = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2-signed.crt"));

		CertificateToken tsa = DSSUtils.loadCertificate(new File("src/test/resources/TSA_BE.cer"));

		logger.info(selfSign.toString());

		logger.info(signed.toString());

		logger.info(tsa.toString());
		logger.info(tsa.getCertificate().toString());

		assertTrue(selfSign.isSelfSigned());
		assertFalse(signed.isSelfSigned());

		assertTrue(tsa.isSignedBy(signed));
		assertTrue(tsa.isSignedBy(selfSign));
	}

	@Test
	public void getMD5Digest() throws UnsupportedEncodingException {
		assertEquals("3e25960a79dbc69b674cd4ec67a72c62", DSSUtils.getMD5Digest("Hello world".getBytes("UTF-8")));
	}
}
