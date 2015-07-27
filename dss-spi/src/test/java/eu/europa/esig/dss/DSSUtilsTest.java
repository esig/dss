package eu.europa.esig.dss;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509CRL;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public class DSSUtilsTest {

	private static CertificateToken certificateWithAIA;

	@BeforeClass
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void getPolicies() {
		List<String> policyIdentifiers = DSSUtils.getPolicyIdentifiers(certificateWithAIA.getCertificate());
		assertTrue(CollectionUtils.isNotEmpty(policyIdentifiers));
		assertTrue(policyIdentifiers.contains("1.3.171.1.1.10.8.1"));
	}

	@Test
	public void getQCStatementsIdList() {
		List<String> qcStatementsIdList = DSSUtils.getQCStatementsIdList(certificateWithAIA.getCertificate());
		assertTrue(CollectionUtils.isEmpty(qcStatementsIdList));

		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		qcStatementsIdList = DSSUtils.getQCStatementsIdList(certificate.getCertificate());
		assertTrue(CollectionUtils.isNotEmpty(qcStatementsIdList));
		assertTrue(qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
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
		byte[] byteArray = IOUtils.toByteArray(fis);
		System.out.println(Base64.encodeBase64String(byteArray));
		IOUtils.closeQuietly(fis);
		CertificateToken certificate2 = DSSUtils.loadCertificate(byteArray);
		assertNotNull(certificate2);

		CertificateToken certificateNew = DSSUtils.loadCertificate(new FileInputStream("src/test/resources/belgiumrs2-new.crt"));
		assertNotNull(certificateNew);

		FileInputStream fisNew = new FileInputStream("src/test/resources/belgiumrs2-new.crt");
		byte[] byteArrayNew = IOUtils.toByteArray(fisNew);
		System.out.println(Base64.encodeBase64String(byteArrayNew));
		IOUtils.closeQuietly(fisNew);
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

	@Test
	public void convertToPEM() {
		String convertToPEM = DSSUtils.convertToPEM(certificateWithAIA);
		CertificateToken certificate = DSSUtils.loadCertificate(convertToPEM.getBytes());
		assertTrue(certificate.equals(certificateWithAIA));
	}

	@Test
	public void loadCrl() throws Exception {
		X509CRL crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/belgium2.crl"));
		assertNotNull(crl);
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
}
