/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSSUtilsTest {

	private static final Logger logger = LoggerFactory.getLogger(DSSUtilsTest.class);

	private static CertificateToken certificateWithAIA;

	@BeforeAll
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void digest() {
		Security.addProvider(DSSSecurityProvider.getSecurityProvider());

		byte[] data = "Hello world!".getBytes(StandardCharsets.UTF_8);
		assertEquals("d3486ae9136e7856bc42212385ea797094475802", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, data)));
		assertEquals("7e81ebe9e604a0c97fef0e4cfe71f9ba0ecba13332bde953ad1c66e4", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA224, data)));
		assertEquals("c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA256, data)));
		assertEquals("f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad6094f517a2182360c9aacf6a3dc323162cb6fd8cdffedb0fe038f55e85ffb5b6",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA512, data)));

		assertEquals("d3ee9b1ba1990fecfd794d2f30e0207aaa7be5d37d463073096d86f8", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA3_224, data)));
		assertEquals("d6ea8f9a1f22e1298e5a9506bd066f23cc56001f5d36582344a628649df53ae8", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA3_256, data)));
		assertEquals("f9210511d0b2862bdcb672daa3f6a4284576ccb24d5b293b366b39c24c41a6918464035ec4466b12e22056bf559c7a49",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA3_384, data)));
		assertEquals("95decc72f0a50ae4d9d5378e1b2252587cfc71977e43292c8f1b84648248509f1bc18bc6f0b0d0b8606a643eff61d611ae84e6fbd4a2683165706bd6fd48b334",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA3_512, data)));

		assertEquals("ee8ee3ada079996b80d926eef439a502", Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE128, data)));
		assertEquals("e80627c7a1dd02229936bb2822572025e17b91ef3a94f7ade9d810aee8d6a873",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE256, data)));

		// BC JCAJCE
		// org.bouncycastle.jcajce.provider.digest.DigestShake256_512
		String shake256_512 = "e80627c7a1dd02229936bb2822572025e17b91ef3a94f7ade9d810aee8d6a873f3d6795a6f7b042a3b65ba0faa872f32e513eb8f460dc60768ee86a05d22e7ac";
		assertEquals(512, Utils.fromHex(shake256_512).length * 8);
		assertEquals(shake256_512,
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE256_512, data)));
	}

	@Test
	public void testLoadIssuer() {
		Collection<CertificateToken> issuers = DSSUtils.loadPotentialIssuerCertificates(certificateWithAIA, new NativeHTTPDataLoader());
		assertNotNull(issuers);
		assertFalse(issuers.isEmpty());
		boolean foundIssuer = false;
		for (CertificateToken issuer : issuers) {
			if (certificateWithAIA.isSignedBy(issuer)) {
				foundIssuer = true;
			}
		}
		assertTrue(foundIssuer);
	}

	@Test
	public void testDontSkipCertificatesWhenMultipleAreFoundInP7c() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/certchain.p7c")) {
			DSSException exception = assertThrows(DSSException.class, () -> DSSUtils.loadCertificate(fis));
			assertEquals("Could not parse certificate", exception.getMessage());
		}
	}

	@Test
	public void testLoadP7cPEM() throws DSSException, IOException {
		Collection<CertificateToken> certs = DSSUtils.loadCertificateFromP7c(new FileInputStream("src/test/resources/certchain.p7c"));
		assertTrue(Utils.isCollectionNotEmpty(certs));
		assertTrue(certs.size() > 1);
	}

	@Test
	public void testLoadP7cNotPEM() throws DSSException, IOException {
		Collection<CertificateToken> certs = DSSUtils.loadCertificateFromP7c(new FileInputStream("src/test/resources/AdobeCA.p7c"));
		assertTrue(Utils.isCollectionNotEmpty(certs));
	}

	@Test
	public void testLoadIssuerEmptyDataLoader() {
		assertTrue(DSSUtils.loadPotentialIssuerCertificates(certificateWithAIA, null).isEmpty());
	}

	@Test
	public void testLoadIssuerNoAIA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		assertTrue(DSSUtils.loadPotentialIssuerCertificates(certificate, new NativeHTTPDataLoader()).isEmpty());
		assertTrue(certificate.isCA());
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

	@Test
	public void loadCertificateDoesNotThrowNullPointerExceptionWhenProvidedNonCertificateFile() throws IOException {
		try (ByteArrayInputStream bais = new ByteArrayInputStream("test".getBytes("UTF-8"))) {
			assertThrows(DSSException.class, () -> DSSUtils.loadCertificate(bais));
		}
	}

	@Test
	public void convertToPEM() {
		String convertToPEM = DSSUtils.convertToPEM(certificateWithAIA);

		assertFalse(DSSUtils.isStartWithASN1SequenceTag(new ByteArrayInputStream(convertToPEM.getBytes())));

		CertificateToken certificate = DSSUtils.loadCertificate(convertToPEM.getBytes());
		assertEquals(certificate, certificateWithAIA);

		byte[] certDER = DSSUtils.convertToDER(convertToPEM);
		assertTrue(DSSUtils.isStartWithASN1SequenceTag(new ByteArrayInputStream(certDER)));

		CertificateToken certificate2 = DSSUtils.loadCertificate(certDER);
		assertEquals(certificate2, certificateWithAIA);
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
		assertTrue(rootCA2.isCA());

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

		assertFalse(tsa.isCA());
		assertTrue(tsa.isSignedBy(signed));
		assertTrue(tsa.isSignedBy(selfSign));
	}

	@Test
	public void getMD5Digest() throws UnsupportedEncodingException {
		assertEquals("3e25960a79dbc69b674cd4ec67a72c62", DSSUtils.getMD5Digest("Hello world".getBytes("UTF-8")));
	}

	@Test
	public void getDeterministicId() {

		Calendar calendar = Calendar.getInstance();

		Date d1 = calendar.getTime();

		String deterministicId = DSSUtils.getDeterministicId(d1, certificateWithAIA.getDSSId());
		assertNotNull(deterministicId);
		String deterministicId2 = DSSUtils.getDeterministicId(d1, certificateWithAIA.getDSSId());
		assertEquals(deterministicId, deterministicId2);
		assertNotNull(DSSUtils.getDeterministicId(null, certificateWithAIA.getDSSId()));

		calendar.add(Calendar.MILLISECOND, 1);
		Date d2 = calendar.getTime();

		String deterministicId3 = DSSUtils.getDeterministicId(d2, certificateWithAIA.getDSSId());
		
		assertNotEquals(deterministicId2, deterministicId3);
	}

	@Test
	public void isSelfSigned() {
		CertificateToken selfSign = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrca2-self-sign.crt"));
		assertTrue(selfSign.isSelfSigned());
		assertTrue(selfSign.isSelfIssued());

		CertificateToken cert = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIB+jCCAWOgAwIBAgIGE3w6Wr8TMA0GCSqGSIb3DQEBBQUAMDYxITAfBgNVBAMMGFJvb3RJc3N1ZXJTZWxmU2lnbmVkRmFrZTERMA8GA1UECgwIRFNTLXRlc3QwHhcNMTUwMjE3MTYxMTM4WhcNMTUwMjI4MTYxMTM4WjA3MSIwIAYDVQQDDBlSb290U3ViamVjdFNlbGZTaWduZWRGYWtlMREwDwYDVQQKDAhEU1MtdGVzdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqwNS7KYkSvJw8oDzUknI20lcuUWyaY3EBk83a8u3puluyw7C8PLjwScIwd6+sHm20OWgpS+h7RNOatP+6VEDxS2IbDtwKzGlii3SV1HbHWf+rqRnQFnhq7/5FIAEg7/+lK6Lhox/+n+zTq2hMEARU9rc1CHdbywh9JPwO6zkxbECAwEAAaMSMBAwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBBQUAA4GBAASVNBDdoCRo/X6FiJMolH4+acjIbCcIMF5tlsIVf0TauTEsVQE4j+OlLSiY+SRnHlNRvSR7v+8V62QsFVne6Nx+OKs1blwTeOIYFP7g0RBHja8Vtl+Jx4LCC7JI7V3IWFYidCrZp8m70HBY8E4CTeQMgzUrH/ej5V0siL2NdUeh");
		PublicKey publicKey = cert.getPublicKey();
		boolean signedWithItsPublicKey = false;
		try {
			cert.getCertificate().verify(publicKey);
			signedWithItsPublicKey = true;
		} catch (Exception e) {
		}
		assertTrue(signedWithItsPublicKey);
		assertFalse(cert.isSelfIssued());
		assertFalse(cert.isSelfSigned());
	}

	@Test
	public void printSecurityProviders() {
		assertDoesNotThrow(() -> DSSUtils.printSecurityProviders());
	}

	@Test
	public void decodeURI() {
		assertEquals("012éù*34ä5µ£ 6789~#%&()+=`@{[]}'.txt",
				DSSUtils.decodeURI("012%C3%A9%C3%B9*34%C3%A45%C2%B5%C2%A3%206789%7E%23%25%26%28%29%2B%3D%60%40%7B%5B%5D%7D%27.txt"));

		assertEquals("012éù*34ä5µ£ 6789~#%&()+=` @{[]}'.txt",
				DSSUtils.decodeURI("012%C3%A9%C3%B9*34%C3%A45%C2%B5%C2%A3%206789%7E%23%25%26%28%29%2B%3D%60%20%40%7B%5B%5D%7D%27.txt"));

		assertEquals("012éù*34ä5µ£ 6789~#&()+=` @{[]}'.txt",
				DSSUtils.decodeURI("012éù*34ä5µ£ 6789~#&()+=` @{[]}'.txt"));
	}

	@Test
	public void testRSASSAPSS() {
		CertificateToken token = DSSUtils.loadCertificate(this.getClass().getResourceAsStream("/BA-QC-Wurzel-CA-2_PN.txt"));
		assertTrue(token.isSelfSigned());
		assertTrue(token.isSignedBy(token));
		assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, token.getSignatureAlgorithm());
	}
	
	@Test
	public void getUTCDateTest() throws Exception {
		String pattern = "yyyy-MM-dd HH:mm:ss";
		SimpleDateFormat dateFormat = new SimpleDateFormat(pattern);
		dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		
		Date date = DSSUtils.getUtcDate(2001, 0, 1);
		String formattedDate = dateFormat.format(date);
		assertEquals("2001-01-01 00:00:00", formattedDate);
		
		Date parsedDate = dateFormat.parse(formattedDate);
		assertEquals(date, parsedDate);
	}
	
	@Test
	public void removeControlCharactersTest() {
		assertEquals(" ", DSSUtils.removeControlCharacters(" "));
		assertEquals("Nowina Solutions", DSSUtils.removeControlCharacters("Nowina Solutions"));
		assertEquals("Новина", DSSUtils.removeControlCharacters("Новина"));
		assertEquals("πτλς", DSSUtils.removeControlCharacters("πτλς"));
		assertEquals("ხელმოწერა", DSSUtils.removeControlCharacters("ხელმოწერა"));
		assertEquals("", DSSUtils.removeControlCharacters("\n"));
		assertEquals("", DSSUtils.removeControlCharacters("\r\n"));
		assertEquals("http://xadessrv.plugtests.net/capso/ocsp?ca=RotCAOK", DSSUtils.removeControlCharacters(
				new String(Utils.fromBase64("aHR0cDovL3hhZGVzc3J2LnBsdWd0ZXN0cy5uZXQvY2Fwc28vb2NzcD9jYT1SAG90Q0FPSw=="))));
	}

	@Test
	public void replaceAllNonAlphanumericCharactersTest() {
		assertEquals("-", DSSUtils.replaceAllNonAlphanumericCharacters(" ", "-"));
		assertEquals("Nowina-Solutions", DSSUtils.replaceAllNonAlphanumericCharacters("Nowina Solutions", "-"));
		assertEquals("Новина", DSSUtils.replaceAllNonAlphanumericCharacters("Новина", "?"));
		assertEquals("πτλς", DSSUtils.replaceAllNonAlphanumericCharacters("πτλς", "?"));
		assertEquals("ხელმოწერა", DSSUtils.replaceAllNonAlphanumericCharacters("ხელმოწერა", "?"));
		assertEquals("?", DSSUtils.replaceAllNonAlphanumericCharacters("\n", "?"));
		assertEquals("?", DSSUtils.replaceAllNonAlphanumericCharacters("\r\n", "?"));
		assertEquals("?", DSSUtils.replaceAllNonAlphanumericCharacters("---____   ??? !!!!", "?"));
	}

	@Test
	public void loadEdDSACert() throws NoSuchAlgorithmException, IOException {

		// RFC 8410

		Security.addProvider(DSSSecurityProvider.getSecurityProvider());
		
		CertificateToken token = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZXN0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQDDA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJjga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAgBgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cgw1AH9efZBw==");
		assertNotNull(token);
		logger.info("{}", token);
		logger.info("{}", token.getPublicKey());
		assertFalse(token.isSelfSigned());
		assertFalse(token.isSignedBy(token));
		assertEquals(SignatureAlgorithm.ED25519, token.getSignatureAlgorithm());
		assertTrue(token.checkKeyUsage(KeyUsageBit.KEY_AGREEMENT));
		assertEquals(EncryptionAlgorithm.X25519, EncryptionAlgorithm.forKey(token.getPublicKey()));

		X509CertificateHolder holder = new X509CertificateHolder(token.getEncoded());
		SubjectPublicKeyInfo subjectPublicKeyInfo = holder.getSubjectPublicKeyInfo();
		assertNotNull(subjectPublicKeyInfo);
		assertEquals(EncryptionAlgorithm.X25519.getOid(), subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId());

		token = DSSUtils
				.loadCertificateFromBase64EncodedString(
				"MIIBCDCBuwIUGW78zw0OL0GptJi++a91dBa7DsQwBQYDK2VwMCcxCzAJBgNVBAYTAkRFMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wHhcNMTkwMzMxMTc1MTIyWhcNMjEwMjI4MTc1MTIyWjAnMQswCQYDVQQGEwJERTEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMCowBQYDK2VwAyEAK87g0b8CC1eA5mvKXt9uezZwJYWEyg74Y0xTZEkqCcwwBQYDK2VwA0EAIIu/aa3Qtr3IE5to/nvWVY9y3ciwG5DnA70X3ALUhFs+U5aLtfY8sNT1Ng72ht+UBwByuze20UsL9qMsmknQCA==");
		assertNotNull(token);
		logger.info("{}", token);
		logger.info("{}", token.getPublicKey());
		assertEquals(SignatureAlgorithm.ED25519, token.getSignatureAlgorithm());
		assertEquals(EncryptionAlgorithm.EDDSA, EncryptionAlgorithm.forKey(token.getPublicKey()));
		assertTrue(token.isSelfSigned());
		assertTrue(token.isSignedBy(token));
	}

	@Test
	public void isUrnOidTest() {
		assertFalse(DSSUtils.isUrnOid(null));
		assertFalse(DSSUtils.isUrnOid(""));
		assertFalse(DSSUtils.isUrnOid("aurn:oid:1.2.3.4"));
		assertTrue(DSSUtils.isUrnOid("urn:oid:1.2.3.4"));
		assertTrue(DSSUtils.isUrnOid("URN:OID:1.2.3.4"));
	}
	
	@Test
	public void isOidCode() {
		assertFalse(DSSUtils.isOidCode(null));
		assertFalse(DSSUtils.isOidCode(""));
		assertFalse(DSSUtils.isOidCode("aurn:oid:1.2.3.4"));
		assertFalse(DSSUtils.isOidCode("http://sample.com"));
		assertFalse(DSSUtils.isOidCode("25.25"));
		assertFalse(DSSUtils.isOidCode("0.4.00.1733.2"));
		assertTrue(DSSUtils.isOidCode("1.2.3.4"));
		assertTrue(DSSUtils.isOidCode("1.3.6.1.4.1.343"));
		assertTrue(DSSUtils.isOidCode("0.4.0.1733.2"));
		assertTrue(DSSUtils.isOidCode("0.4.0.19122.1"));
		assertTrue(DSSUtils.isOidCode("2.16.840.1.113883.3.3190.100"));
	}
	
	@Test
	public void getOidCodeTest() {
		assertEquals(null, DSSUtils.getOidCode(null));
		assertEquals("", DSSUtils.getOidCode(""));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("aurn:oid:1.2.3.4"));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("urn:oid:1.2.3.4"));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("URN:OID:1.2.3.4"));
		assertEquals("urn.oid.1.2.3.4", DSSUtils.getOidCode("urn.oid.1.2.3.4"));
	}
	
	@Test
	public void stripFirstLeadingOccuranceTest() {
		assertEquals(null, DSSUtils.stripFirstLeadingOccurrence(null, null));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", null));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", ""));
		assertEquals("aabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "a"));
		assertEquals("bbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "aaa"));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "aaaa"));
		assertEquals("", DSSUtils.stripFirstLeadingOccurrence("application/", "application/"));
		assertEquals("json", DSSUtils.stripFirstLeadingOccurrence("application/json", "application/"));
		assertEquals("application/json", DSSUtils.stripFirstLeadingOccurrence("application/application/json", "application/"));
	}

}
