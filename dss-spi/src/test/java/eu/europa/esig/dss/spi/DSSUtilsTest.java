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
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSSUtilsTest {

	private static final Logger logger = LoggerFactory.getLogger(DSSUtilsTest.class);

	private static CertificateToken certificate;

	@BeforeAll
	public static void init() {
		certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificate);
	}

	@Test
	public void formatDateTest() {
		Calendar calendar = Calendar.getInstance(DSSUtils.UTC_TIMEZONE);
		calendar.set(2021, 0, 01, 0, 0, 0);
		assertEquals("2021-01-01T00:00:00Z", DSSUtils.formatDateToRFC(calendar.getTime()));
		assertEquals("2021-01-01T00:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT));
		assertEquals("2021-01-01T03:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, "GMT+3"));
		assertEquals("2021-01-01T03:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, TimeZone.getTimeZone("GMT+3")));
		assertEquals("2020-12-31T21:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, "GMT-3"));

		final String customDateFormat = "yyyy-MM-dd HH:mm";
		assertEquals("2021-01-01 00:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat));
		assertEquals("2021-01-01 03:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, "GMT+3"));
		assertEquals("2021-01-01 03:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, TimeZone.getTimeZone("GMT+3")));
		assertEquals("2020-12-31 21:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, "GMT-3"));

		calendar = Calendar.getInstance(TimeZone.getTimeZone("GMT+3"));
		calendar.set(2021, 0, 01, 0, 0, 0);
		assertEquals("2020-12-31T21:00:00Z", DSSUtils.formatDateToRFC(calendar.getTime()));
		assertEquals("2020-12-31T21:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT));
		assertEquals("2021-01-01T00:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, "GMT+3"));
		assertEquals("2021-01-01T00:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, TimeZone.getTimeZone("GMT+3")));
		assertEquals("2020-12-31T18:00:00Z", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), DSSUtils.RFC3339_TIME_FORMAT, "GMT-3"));

		assertEquals("2020-12-31 21:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat));
		assertEquals("2021-01-01 00:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, "GMT+3"));
		assertEquals("2021-01-01 00:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, TimeZone.getTimeZone("GMT+3")));
		assertEquals("2020-12-31 18:00", DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, "GMT-3"));

		calendar = Calendar.getInstance();
		calendar.set(2021, 0, 01, 0, 0, 0);
		assertEquals(DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, Calendar.getInstance().getTimeZone()),
				DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, ""));
		assertEquals(DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, Calendar.getInstance().getTimeZone()),
				DSSUtils.formatDateWithCustomFormat(calendar.getTime(), customDateFormat, (TimeZone) null));
	}

	@Test
	public void digestTest() {
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

		assertEquals("ee8ee3ada079996b80d926eef439a5022faf7a8b9cf69154e6ee46020ea2eafd",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE128, data)));
		assertEquals("e80627c7a1dd02229936bb2822572025e17b91ef3a94f7ade9d810aee8d6a873f3d6795a6f7b042a3b65ba0faa872f32e513eb8f460dc60768ee86a05d22e7ac",
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE256, data)));

		// BC JCAJCE
		// org.bouncycastle.jcajce.provider.digest.DigestShake256_512
		String shake256_512 = "e80627c7a1dd02229936bb2822572025e17b91ef3a94f7ade9d810aee8d6a873f3d6795a6f7b042a3b65ba0faa872f32e513eb8f460dc60768ee86a05d22e7ac";
		assertEquals(512, Utils.fromHex(shake256_512).length * 8);
		assertEquals(shake256_512,
				Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHAKE256_512, data)));
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
		String convertToPEM = DSSUtils.convertToPEM(certificate);

		assertFalse(DSSUtils.isStartWithASN1SequenceTag(new ByteArrayInputStream(convertToPEM.getBytes())));

		CertificateToken certificate = DSSUtils.loadCertificate(convertToPEM.getBytes());
		assertEquals(certificate, DSSUtilsTest.certificate);

		byte[] certDER = DSSUtils.convertToDER(convertToPEM);
		assertTrue(DSSUtils.isStartWithASN1SequenceTag(new ByteArrayInputStream(certDER)));

		CertificateToken certificate2 = DSSUtils.loadCertificate(certDER);
		assertEquals(certificate2, DSSUtilsTest.certificate);
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
		assertEquals(-1, tsa.getPathLenConstraint());

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

		String deterministicId = DSSUtils.getDeterministicId(d1, certificate.getDSSId());
		assertNotNull(deterministicId);
		String deterministicId2 = DSSUtils.getDeterministicId(d1, certificate.getDSSId());
		assertEquals(deterministicId, deterministicId2);
		assertNotNull(DSSUtils.getDeterministicId(null, certificate.getDSSId()));

		calendar.add(Calendar.MILLISECOND, 1);
		Date d2 = calendar.getTime();

		String deterministicId3 = DSSUtils.getDeterministicId(d2, certificate.getDSSId());
		
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
		assertNull(DSSUtils.removeControlCharacters(null));
		assertEquals("", DSSUtils.removeControlCharacters(""));
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
		assertNull(DSSUtils.replaceAllNonAlphanumericCharacters(null, "-"));
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
		assertNull(DSSUtils.getOidCode(null));
		assertEquals("", DSSUtils.getOidCode(""));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("aurn:oid:1.2.3.4"));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("urn:oid:1.2.3.4"));
		assertEquals("1.2.3.4", DSSUtils.getOidCode("URN:OID:1.2.3.4"));
		assertEquals("urn.oid.1.2.3.4", DSSUtils.getOidCode("urn.oid.1.2.3.4"));
	}
	
	@Test
	public void stripFirstLeadingOccurrenceTest() {
		assertNull(DSSUtils.stripFirstLeadingOccurrence(null, null));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", null));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", ""));
		assertEquals("aabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "a"));
		assertEquals("bbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "aaa"));
		assertEquals("aaabbcc", DSSUtils.stripFirstLeadingOccurrence("aaabbcc", "aaaa"));
		assertEquals("", DSSUtils.stripFirstLeadingOccurrence("application/", "application/"));
		assertEquals("json", DSSUtils.stripFirstLeadingOccurrence("application/json", "application/"));
		assertEquals("application/json", DSSUtils.stripFirstLeadingOccurrence("application/application/json", "application/"));
	}

	@Test
	public void signAndConvertECSignatureValueTest() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator gen = KeyPairGenerator.getInstance("ECDSA");
		KeyPair pair = gen.generateKeyPair();

		ECPrivateKey ecPrivateKey = (ECPrivateKey) pair.getPrivate();
		signAndCheckSignatureValue("SHA1withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA1), ecPrivateKey);
		signAndCheckSignatureValue("SHA224withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA224), ecPrivateKey);
		signAndCheckSignatureValue("SHA256withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA256), ecPrivateKey);
		signAndCheckSignatureValue("SHA384withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA384), ecPrivateKey);
		signAndCheckSignatureValue("SHA512withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA512), ecPrivateKey);
		signAndCheckSignatureValue("RIPEMD160withECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.RIPEMD160), ecPrivateKey);
		signAndCheckSignatureValue("SHA1withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA1), ecPrivateKey);
		signAndCheckSignatureValue("SHA224withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA224), ecPrivateKey);
		signAndCheckSignatureValue("SHA256withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256), ecPrivateKey);
		signAndCheckSignatureValue("SHA384withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA384), ecPrivateKey);
		signAndCheckSignatureValue("SHA512withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA512), ecPrivateKey);
		signAndCheckSignatureValue("RIPEMD160withPLAIN-ECDSA",
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.RIPEMD160), ecPrivateKey);
	}

	private void signAndCheckSignatureValue(String javaAlgorithm, SignatureAlgorithm currentAlgorithm,
										ECPrivateKey ecPrivateKey) throws Exception {
		Signature s = Signature.getInstance(javaAlgorithm);
		s.initSign(ecPrivateKey);
		s.update("Hello world!".getBytes());
		byte[] originalBinaries = s.sign();
		assertECSignatureValid(originalBinaries, currentAlgorithm);
	}

	@Test
	public void convertECSignatureValueTest() throws Exception {
		assertECSignatureValid(Utils.fromBase64("MEQCIEJNA0AElH/vEH9xLxvqrwCqh+yUh9ACL2vU/2eObRbTAiAxTLSWSioJrfSwPkKcypf+KCHvMGdwZbRWQHnZN2sDnQ=="),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("2B9099C9885DDB5BFDA2E9634905B9A63E7E3A6EC87BDC0A89014716B23F00B0AD787FC8D0DCF28F007E7DEC097F30DA892BE2AC61D90997DCDF05740E4D5B0C"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("947b79069e6a1e3316ec15d696649a4b67c6c188df9bc05458f3b0b94907f3fb52522d4cae24a75735969cff556b1476a5ccbe37ca65a928782c14f299f3b2d3"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("28a1583e58e93a661322f776618d83b023bdc52b2e909cf9d53030b9260ed667b588fd39eeee5b1b55523a7e71cb4187d8b1bbf56c1581fc845863157d279cf5"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("dd8fc5414eda2920d347f3d3f9f604fcf09392a8ce3807f6f87d006cf8ed1959075af8abbb030e6990da52fe49c93486a4b98bb2e18e0f84095175eddabfbb96"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("1daf408ead014bba9f243849ece308b31f898e1ce97b54a78b3c15eb103fa8a1c87bdd97fdfc4cb56a7e1e5650dee2ebfff0b56d5a2ca0338e6ed59689e27ae1323f32b0f93b41987a816c93c00462c68c609692084dbced7308a8a66f0365ee5b7b272273e8abd4ddd4a49d2fd67964bc8c757114791446b9716f3b7f551608"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA512));
		assertECSignatureValid(Utils.fromHex("0d2fc9f18d816e9054af943c392dd46f09da71521de9bd98d765e170f12eb086d3d0f9754105001ed2e703d7290ac967642bc70bdd7a96b5c2b8e3d4b503b80e"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("065a15bd4fec67a2a302d9d3ec679cb8f298f9d6a1d855d3dbf39b3f2fa7ea461e437d9542c4a9527afe5e78c1412937f0dbb05a78380cfb2e1bf6eff944581a"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("f322898717aada9b027855848fa6ec5c4bf84d67a70f0ecbafea9dc90fc1d4f0901325766b199bdcfce1f99a54f0b72e71d740b355fff84a5873fd36c439236e"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("B003267151210F7D8D1A747EEC73A0185CC0E848BF885A9DDE061AB5FB19FB3B6249F8B7B84432738EE80DDAB9654DEA5C4DAB2EC34A5EC8DB17E3DFBF577521"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
		assertECSignatureValid(Utils.fromHex("C511529B789F64466FE1D524AF9279BEED2F12429798FE0B920F9784A6EBB6400081949A7EE84803E823263CD528F5CE503593F00010191D382B092338AF2E96"),
				SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, DigestAlgorithm.SHA256));
	}

	private void assertECSignatureValid(byte[] originalBinaries, SignatureAlgorithm currentAlgorithm) throws Exception {
		SignatureValue signatureValue = new SignatureValue();
		signatureValue.setAlgorithm(currentAlgorithm);
		signatureValue.setValue(originalBinaries);

		SignatureAlgorithm targetAlgorithm;
		if (EncryptionAlgorithm.ECDSA.equals(currentAlgorithm.getEncryptionAlgorithm())) {
			assertTrue(DSSASN1Utils.isAsn1EncodedSignatureValue(originalBinaries));
			targetAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.PLAIN_ECDSA, currentAlgorithm.getDigestAlgorithm());
		} else {
			assertFalse(DSSASN1Utils.isAsn1EncodedSignatureValue(originalBinaries));
			targetAlgorithm = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.ECDSA, currentAlgorithm.getDigestAlgorithm());
		}

		SignatureValue convertedSignatureValue = DSSUtils.convertECSignatureValue(targetAlgorithm, signatureValue);

		if (EncryptionAlgorithm.ECDSA.equals(targetAlgorithm.getEncryptionAlgorithm())) {
			assertTrue(DSSASN1Utils.isAsn1EncodedSignatureValue(convertedSignatureValue.getValue()));
		} else {
			assertFalse(DSSASN1Utils.isAsn1EncodedSignatureValue(convertedSignatureValue.getValue()));
		}

		convertedSignatureValue = DSSUtils.convertECSignatureValue(currentAlgorithm, convertedSignatureValue);
		assertArrayEquals(originalBinaries, convertedSignatureValue.getValue());
	}

	@Test
	public void isLineBreakByteTest() {
		assertTrue(DSSUtils.isLineBreakByte((byte) '\n'));
		assertTrue(DSSUtils.isLineBreakByte((byte) '\r'));
		assertTrue(DSSUtils.isLineBreakByte((byte) 0x0D));
		assertTrue(DSSUtils.isLineBreakByte((byte) 0x0A));
		assertFalse(DSSUtils.isLineBreakByte((byte) 'n'));
		assertFalse(DSSUtils.isLineBreakByte((byte) 'r'));
		assertFalse(DSSUtils.isLineBreakByte((byte) 0x20));
		assertFalse(DSSUtils.isLineBreakByte((byte) 0x6E));
		assertFalse(DSSUtils.isLineBreakByte((byte) 0x72));
	}

	@Test
	public void getObjectIdentifierValue() {
		// Silent processing
		assertEquals("http://website.com", DSSUtils.getObjectIdentifierValue("http://website.com"));
		assertEquals("https://nowina.lu/policy", DSSUtils.getObjectIdentifierValue("https://nowina.lu/policy"));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("1.2.3"));
		assertEquals("1.2.3.4.5", DSSUtils.getObjectIdentifierValue("1.2.3.4.5"));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("urn:oid:1.2.3"));
		assertEquals("1.2.3.4.5", DSSUtils.getObjectIdentifierValue("urn:oid:1.2.3.4.5"));
	}

	@Test
	public void getObjectIdentifierValueWithQualifier() {
		// See DEBUG logs
		assertEquals("http://website.com", DSSUtils.getObjectIdentifierValue("http://website.com", null));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("1.2.3", null));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("urn:oid:1.2.3", null));

		assertEquals("https://nowina.lu/policy", DSSUtils.getObjectIdentifierValue("https://nowina.lu/policy", ObjectIdentifierQualifier.OID_AS_URN));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("1.2.3", ObjectIdentifierQualifier.OID_AS_URN));
		assertEquals("1.2.3.4.5", DSSUtils.getObjectIdentifierValue("urn:oid:1.2.3.4.5", ObjectIdentifierQualifier.OID_AS_URN));

		assertEquals("http://website.com", DSSUtils.getObjectIdentifierValue("http://website.com", ObjectIdentifierQualifier.OID_AS_URI));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("1.2.3", ObjectIdentifierQualifier.OID_AS_URI));
		assertEquals("1.2.3", DSSUtils.getObjectIdentifierValue("urn:oid:1.2.3", ObjectIdentifierQualifier.OID_AS_URI));
	}

	@Test
	public void trimWhitespacesAndNewlinesTest() {
		assertNull(DSSUtils.trimWhitespacesAndNewlines(null));
		assertEquals("", DSSUtils.trimWhitespacesAndNewlines(""));
		assertEquals("", DSSUtils.trimWhitespacesAndNewlines(" "));
		assertEquals("", DSSUtils.trimWhitespacesAndNewlines("\n"));
		assertEquals("", DSSUtils.trimWhitespacesAndNewlines("\r"));
		assertEquals("", DSSUtils.trimWhitespacesAndNewlines("\r\n"));
		assertEquals("1.2.5.3.4", DSSUtils.trimWhitespacesAndNewlines(" 1.2.5.3.4 "));
		assertEquals("http://nowina.lu", DSSUtils.trimWhitespacesAndNewlines("http://nowina.lu \n"));
	}

	@Test
	public void isDocumentEmptyTest() {
		assertTrue(DSSUtils.isEmpty(new InMemoryDocument(new byte[] {})));
		assertTrue(DSSUtils.isEmpty(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY)));
		assertTrue(DSSUtils.isEmpty(InMemoryDocument.createEmptyDocument()));
		assertTrue(DSSUtils.isEmpty(new DigestDocument()));
		assertTrue(DSSUtils.isEmpty(new DigestDocument(DigestAlgorithm.SHA1, DSSUtils.getSHA1Digest("Hello World!"))));
		assertFalse(DSSUtils.isEmpty(new InMemoryDocument(new byte[] { 'a' })));
		assertFalse(DSSUtils.isEmpty(new InMemoryDocument(getClass().getResourceAsStream("/good-user.crt"))));
		assertFalse(DSSUtils.isEmpty(new FileDocument("src/test/resources/good-user.crt")));
	}

}
