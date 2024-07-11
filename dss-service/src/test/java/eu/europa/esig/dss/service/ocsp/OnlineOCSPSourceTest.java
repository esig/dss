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
package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.OnlineSourceTest;
import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.alerts.DSSExternalResourceExceptionAlert;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OnlineOCSPSourceTest extends OnlineSourceTest {

	private static final String CUSTOM_TIMEOUT_OCSP_URL = ONLINE_PKI_HOST + "/ocsp/timeout/%s/%s";

	private static CertificateToken certificateToken;
	private static CertificateToken rootToken;

	private static CertificateToken goodUser;
	private static CertificateToken goodUserOCSPWithReqCertId;
	private static CertificateToken goodCa;
	private static CertificateToken ed25519goodUser;
	private static CertificateToken ed25519goodCa;

	private static CertificateToken invalidSigGoodUser;
	private static CertificateToken timeoutSigGoodUser;
	
	private static CertificateToken qtspUser;
	private static CertificateToken qtspCa;
	private static byte[] qtspOcsp;

	@BeforeAll
	static void init() {
		certificateToken = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		rootToken = DSSUtils.loadCertificate(new File("src/test/resources/CALT.crt"));

		CommonsDataLoader dataLoader = new CommonsDataLoader();
		goodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user.crt"));
		goodUserOCSPWithReqCertId = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-ocsp-certid-digest.crt"));
		goodCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-ca.crt"));

		ed25519goodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/Ed25519-good-user.crt"));
		ed25519goodCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/Ed25519-good-ca.crt"));

		invalidSigGoodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-ocsp-invalid-sig.crt"));
		timeoutSigGoodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-ocsp-timeout.crt"));

		qtspUser = DSSUtils.loadCertificate(new File("src/test/resources/sk_user.cer"));
		qtspCa = DSSUtils.loadCertificate(new File("src/test/resources/sk_ca.cer"));
		qtspOcsp = DSSUtils.toByteArray(new File("src/test/resources/sk_ocsp.bin"));
	}

	@Test
	void testOCSPWithoutNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertTrue(ocspToken.isValid());
	}

	@Test
	void testOCSP() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertTrue(ocspToken.isValid());
	}
	
	@Test
	void testWithCustomDataLoaderConstructor() {
		OCSPDataLoader ocspDataLoader = new OCSPDataLoader();
		OnlineOCSPSource ocspSource = new OnlineOCSPSource(ocspDataLoader);
		OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
	}
	
	@Test
	void testWithSetDataLoader() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(new OCSPDataLoader());
		OCSPToken ocspToken = ocspSource.getRevocationToken(goodUser, goodCa);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
	}

	@Test
	void testOCSPEd25519() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPToken ocspToken = ocspSource.getRevocationToken(ed25519goodUser, ed25519goodCa);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertEquals(SignatureAlgorithm.ED25519, ocspToken.getSignatureAlgorithm());
		assertEquals(SignatureValidity.VALID, ocspToken.getSignatureValidity());
	}

	@Test
	void testOCSPWithNonce() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

	@Test
	void noNonceResponderTest() {
		OnlineOCSPSource ocspSource = new NoNonceSubstituteOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

	@Test
	void noNonceResponderEnforceNonceTest() {
		OnlineOCSPSource ocspSource = new NoNonceSubstituteOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		ocspSource.setAlertOnNonexistentNonce(new DSSExternalResourceExceptionAlert());
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspSource.getRevocationToken(certificateToken, rootToken));
		assertTrue(exception.getMessage().contains("No nonce has been retrieved from OCSP response!"));
	}

	@Test
	void noNonceResponderSilentOnStatusAlertTest() {
		OnlineOCSPSource ocspSource = new NoNonceSubstituteOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		ocspSource.setAlertOnNonexistentNonce(new SilentOnStatusAlert());
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

	@Test
	void getRevocationTokenInvalidSignatureTest() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPToken ocspToken = ocspSource.getRevocationToken(invalidSigGoodUser, goodCa);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertFalse(ocspToken.isValid());
	}

	@Test
	void getRevocationTokenTimeoutTest() {
		OCSPDataLoader dataLoader = new OCSPDataLoader();
		dataLoader.setTimeoutResponse(1000);

		OnlineOCSPSource ocspSource = new OnlineOCSPSource(dataLoader);

		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspSource.getRevocationToken(timeoutSigGoodUser, goodCa));
		assertTrue(exception.getMessage().contains("Unable to retrieve OCSP response for certificate with Id '" + timeoutSigGoodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));

		String alternativeUrl = String.format(CUSTOM_TIMEOUT_OCSP_URL, 1, DSSASN1Utils.getSubjectCommonName(goodCa));
		AlternateUrlsSourceAdapter<OCSP> ocspAlternativeUrlSource = new AlternateUrlsSourceAdapter<>(ocspSource, Collections.singletonList(alternativeUrl));

		RevocationToken<OCSP> revocationToken = ocspAlternativeUrlSource.getRevocationToken(timeoutSigGoodUser, goodCa);
		assertInstanceOf(OCSPToken.class, revocationToken);

		OCSPToken ocspToken = (OCSPToken) revocationToken;
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
		assertTrue(ocspToken.isValid());

		alternativeUrl = String.format(CUSTOM_TIMEOUT_OCSP_URL, 2000, DSSASN1Utils.getSubjectCommonName(goodCa));
		AlternateUrlsSourceAdapter<OCSP> ocspFailedAlternativeUrlSource = new AlternateUrlsSourceAdapter<>(ocspSource, Collections.singletonList(alternativeUrl));
		exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspFailedAlternativeUrlSource.getRevocationToken(timeoutSigGoodUser, goodCa));
		assertTrue(exception.getMessage().contains("Unable to retrieve OCSP response for certificate with Id '" + timeoutSigGoodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));
	}

	@Test
	void invalidNonceResponderTest() {
		OnlineOCSPSource ocspSource = new InvalidNonceSubstituteOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspSource.getRevocationToken(certificateToken, rootToken));
		assertTrue(exception.getMessage().contains("does not match a dispatched nonce"));
	}

	@Test
	void invalidNonceResponderSilentOnStatusTest() {
		OnlineOCSPSource ocspSource = new InvalidNonceSubstituteOCSPSource();
		ocspSource.setNonceSource(new SecureRandomNonceSource());
		ocspSource.setAlertOnInvalidNonce(new SilentOnStatusAlert());
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}

	@Test
	void noNextUpdateTest() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setAlertOnInvalidUpdateTime(new DSSExternalResourceExceptionAlert());
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspSource.getRevocationToken(certificateToken, rootToken));
		assertTrue(exception.getMessage().contains("Obtained OCSP Response does not contain nextUpdate field!"));
	}

	@Test
	void validNextUpdateTest() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		OCSPToken ocspToken = ocspSource.getRevocationToken(qtspUser, qtspCa);
		assertNotNull(ocspToken);
	}

	@Test
	void validNextUpdateEnforcedTest() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setAlertOnInvalidUpdateTime(new DSSExternalResourceExceptionAlert());
		OCSPToken ocspToken = ocspSource.getRevocationToken(qtspUser, qtspCa);
		assertNotNull(ocspToken);
	}

	@Test
	void invalidNextUpdateTest() {
		OnlineOCSPSource ocspSource = new SubstituteOCSPSource(qtspOcsp);
		OCSPToken ocspToken = ocspSource.getRevocationToken(qtspUser, qtspCa);
		assertNotNull(ocspToken);
	}

	@Test
	void invalidNextUpdateEnforcedTest() {
		OnlineOCSPSource ocspSource = new SubstituteOCSPSource(qtspOcsp);
		ocspSource.setAlertOnInvalidUpdateTime(new DSSExternalResourceExceptionAlert());
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> ocspSource.getRevocationToken(qtspUser, qtspCa));
		assertTrue(exception.getMessage().contains("The current time"));
	}

	@Test
	void invalidNextUpdateWithLargeToleranceTest() {
		OnlineOCSPSource ocspSource = new SubstituteOCSPSource(qtspOcsp);
		ocspSource.setAlertOnInvalidUpdateTime(new DSSExternalResourceExceptionAlert());
		ocspSource.setNextUpdateTolerancePeriod(1000L * 60 * 60 * 24 * 365 * 20); // 20 years
		OCSPToken ocspToken = ocspSource.getRevocationToken(qtspUser, qtspCa);
		assertNotNull(ocspToken);
	}

	@Test
	void testOCSPWithFileCache() {
		File cacheFolder = new File("target/ocsp-cache");

		// clean cache if exists
		if (cacheFolder.exists()) {
			Arrays.asList(Objects.requireNonNull(cacheFolder.listFiles())).forEach(File::delete);
		}
		
		/* 1) Test default behavior of OnlineOCSPSource */
		
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());

		/* 2) Test OnlineOCSPSource with a custom FileCacheDataLoader (without online loader) */
		
		// create a FileCacheDataLoader
		FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
		fileCacheDataLoader.setFileCacheDirectory(cacheFolder);
		fileCacheDataLoader.setCacheExpirationTime(5000);
		fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());
		
		assertTrue(cacheFolder.exists());
		
		// nothing in cache
		OnlineOCSPSource onlineOCSPSource = new OnlineOCSPSource(fileCacheDataLoader);
		Exception exception = assertThrows(DSSExternalResourceException.class, () -> onlineOCSPSource.getRevocationToken(certificateToken, rootToken));
		assertTrue(exception.getMessage().contains("Unable to retrieve OCSP response for certificate with Id "));

		/* 3) Test OnlineOCSPSource with a custom FileCacheDataLoader (with online loader) */

		fileCacheDataLoader.setDataLoader(new OCSPDataLoader());
		ocspSource = new OnlineOCSPSource(fileCacheDataLoader);
		
		// load from online
		ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());

		/* 4) Test OnlineOCSPSource with a custom FileCacheDataLoader (loading from cache) */
		
		fileCacheDataLoader.setDataLoader(new IgnoreDataLoader());

		// load from cache
		ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());

		/* 5) Test OnlineOCSPSource with setDataLoader(fileCacheDataLoader) method */
		
		// test setDataLoader(dataLoader)
		ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(fileCacheDataLoader);
		
		ocspToken = ocspSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
		assertNotNull(ocspToken.getBasicOCSPResp());
	}

	@Test
	void testInjectExternalUrls() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		List<String> alternativeOCSPUrls = new ArrayList<>();
		alternativeOCSPUrls.add("http://wrong.url.com");

		RevocationSource<OCSP> currentOCSPSource = new AlternateUrlsSourceAdapter<>(ocspSource,
				alternativeOCSPUrls);
		OCSPToken ocspToken = (OCSPToken) currentOCSPSource.getRevocationToken(certificateToken, rootToken);
		assertNotNull(ocspToken);
	}
	
	@Test
	void customCertIDDigestAlgorithmTest() {
		OCSPDataLoader dataLoader = new OCSPDataLoader();
		dataLoader.setTimeoutConnection(10000);
		dataLoader.setTimeoutSocket(10000);

		OnlineOCSPSource ocspSource = new OnlineOCSPSource(dataLoader);

		OCSPToken ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
		assertNotNull(ocspToken);
		assertEquals(SignatureAlgorithm.RSA_SHA1, ocspToken.getSignatureAlgorithm()); // default value
		
		ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA256);
		ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
		assertEquals(SignatureAlgorithm.RSA_SHA256, ocspToken.getSignatureAlgorithm());

		ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA512);
		ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
		assertEquals(SignatureAlgorithm.RSA_SHA512, ocspToken.getSignatureAlgorithm());

		ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA3_256);
		ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
		assertEquals(SignatureAlgorithm.RSA_SHA3_256, ocspToken.getSignatureAlgorithm());

		ocspSource.setCertIDDigestAlgorithm(DigestAlgorithm.SHA3_512);
		ocspToken = ocspSource.getRevocationToken(goodUserOCSPWithReqCertId, goodCa);
		assertEquals(SignatureAlgorithm.RSA_SHA3_512, ocspToken.getSignatureAlgorithm());
	}

	@Test
	void testNullDataLoader() {
		OnlineOCSPSource ocspSource = new OnlineOCSPSource();
		ocspSource.setDataLoader(null);

		Exception exception = assertThrows(NullPointerException.class,
				() -> ocspSource.getRevocationToken(certificateToken, rootToken));
		assertEquals("DataLoader is not provided !", exception.getMessage());
	}

	private static class NoNonceSubstituteOCSPSource extends OnlineOCSPSource {

		private static final long serialVersionUID = 8123906984792075209L;

		private NoNonceSubstituteOCSPSource() {
			super();
		}

		@Override
		protected byte[] buildOCSPRequest(CertificateToken certificateToken, CertificateToken issuerToken, byte[] nonce) {
			return super.buildOCSPRequest(certificateToken, issuerToken, null);
		}

	}

	private static class InvalidNonceSubstituteOCSPSource extends OnlineOCSPSource {

		private static final long serialVersionUID = -5857935431031029816L;

		private InvalidNonceSubstituteOCSPSource() {
			super();
		}
		@Override
		protected byte[] buildOCSPRequest(CertificateToken certificateToken, CertificateToken issuerToken, byte[] nonce) {
			return super.buildOCSPRequest(certificateToken, issuerToken, new SecureRandomNonceSource().getNonceValue());
		}

	}

	private static class SubstituteOCSPSource extends OnlineOCSPSource {

		private static final long serialVersionUID = 9135834387628029175L;

		private SubstituteOCSPSource(final byte[] ocspResponse) {
			super(new SubstituteOCSPDataLoader(ocspResponse));
		}

	}

	private static class SubstituteOCSPDataLoader extends CommonsDataLoader {

		private static final long serialVersionUID = -7023354489321956369L;
		
		private final byte[] ocspResponse;

		private SubstituteOCSPDataLoader(final byte[] ocspResponse) {
			this.ocspResponse = ocspResponse;
		}

		@Override
		public byte[] post(String url, byte[] content) {
			return ocspResponse;
		}
		
	}
	
}
