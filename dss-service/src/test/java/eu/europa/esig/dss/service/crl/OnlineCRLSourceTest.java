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
package eu.europa.esig.dss.service.crl;

import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.service.OnlineSourceTest;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.AlternateUrlsSourceAdapter;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OnlineCRLSourceTest extends OnlineSourceTest {

	private static final String ALTERNATIVE_URL = ONLINE_PKI_HOST + "/crl/root-ca.crl";
	private static final String WRONG_URL = "http://wrong.url";
	private static final String CUSTOM_TIMEOUT_CRL_URL = ONLINE_PKI_HOST + "/crl/timeout/%s/%s.crl";
	
	private static OnlineCRLSource onlineCRLSource;
	private static CommonsDataLoader dataLoader;

	private static CertificateToken goodUser;
	private static CertificateToken goodCa;
	private static CertificateToken rootCa;

	private static CertificateToken ed25519goodUser;
	private static CertificateToken ed25519goodCa;
	private static CertificateToken ed25519RootCa;

	private static CertificateToken invalidSigGoodUser;
	private static CertificateToken timeoutSigGoodUser;

	@BeforeAll
	public static void init() {
		dataLoader = new CommonsDataLoader();

		goodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user.crt"));
		goodCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-ca.crt"));
		rootCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/root-ca.crt"));

		ed25519goodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/Ed25519-good-user.crt"));
		ed25519goodCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/Ed25519-good-ca.crt"));
		ed25519RootCa = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/Ed25519-root-ca.crt"));

		invalidSigGoodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-crl-invalid-sig.crt"));
		timeoutSigGoodUser = DSSUtils.loadCertificate(dataLoader.get(ONLINE_PKI_HOST + "/crt/good-user-crl-timeout.crt"));
	}

	@BeforeEach
	public void beforeEach() {
		dataLoader.setTimeoutResponse(60000);
		onlineCRLSource = new OnlineCRLSource(dataLoader);
	}
	
	@Test
	public void getRevocationTokenTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa));
		assertEquals("No CRL location found for certificate with Id '" + goodUser.getDSSIdAsString() + "'", exception.getMessage());
		
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa);
		assertNotNull(revocationToken);
		assertTrue(revocationToken.isValid());
	}
	
	@Test
	public void getRevocationTokenEd25519Test() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(ed25519goodCa, ed25519goodUser));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + ed25519goodCa.getDSSIdAsString() + "'"));

		CRLToken revocationToken = onlineCRLSource.getRevocationToken(ed25519goodCa, ed25519RootCa);
		assertNotNull(revocationToken);
		assertTrue(revocationToken.isSignatureIntact());
		assertTrue(revocationToken.isValid());
		assertEquals(SignatureAlgorithm.ED25519, revocationToken.getSignatureAlgorithm());
		assertEquals(SignatureValidity.VALID, revocationToken.getSignatureValidity());
	}

	@Test
	public void getRevocationTokenInvalidSignatureTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(invalidSigGoodUser, goodCa));
		assertTrue(exception.getMessage().contains("CRL Signature cannot be validated : CRL does not verify with supplied public key."));
	}

	@Test
	public void getRevocationTokenTimeoutTest() {
		dataLoader.setTimeoutResponse(1000);

		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(timeoutSigGoodUser, goodCa));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + timeoutSigGoodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));

		String alternativeUrl = String.format(CUSTOM_TIMEOUT_CRL_URL, 1, DSSASN1Utils.getSubjectCommonName(goodCa));
		AlternateUrlsSourceAdapter<CRL> CRLAlternativeUrlSource = new AlternateUrlsSourceAdapter<>(onlineCRLSource, Collections.singletonList(alternativeUrl));

		RevocationToken<CRL> revocationToken = CRLAlternativeUrlSource.getRevocationToken(timeoutSigGoodUser, goodCa);
		assertInstanceOf(CRLToken.class, revocationToken);

		CRLToken crlToken = (CRLToken) revocationToken;
		assertNotNull(crlToken);
		assertTrue(crlToken.isValid());

		alternativeUrl = String.format(CUSTOM_TIMEOUT_CRL_URL, 2000, DSSASN1Utils.getSubjectCommonName(goodCa));
		AlternateUrlsSourceAdapter<CRL> crlFailedAlternativeUrlSource = new AlternateUrlsSourceAdapter<>(onlineCRLSource, Collections.singletonList(alternativeUrl));
		exception = assertThrows(DSSExternalResourceException.class,
				() -> crlFailedAlternativeUrlSource.getRevocationToken(timeoutSigGoodUser, goodCa));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + timeoutSigGoodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));
	}

	@Test
	public void getRevocationTokenWithAlternateUrlTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Collections.singletonList(ALTERNATIVE_URL)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));
		
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Collections.singletonList(ALTERNATIVE_URL));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void getRevocationTokenWithWrongAlternateUrlTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Collections.singletonList(WRONG_URL)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));

		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Collections.singletonList(WRONG_URL));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void timeoutTest() {
		dataLoader.setTimeoutResponse(1);

		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Arrays.asList(WRONG_URL, ALTERNATIVE_URL)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));

		exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodCa, rootCa, Arrays.asList(WRONG_URL, ALTERNATIVE_URL)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodCa.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));
	}

	@Test
	public void testNullDataLoader() {
		onlineCRLSource.setDataLoader(null);

		Exception exception = assertThrows(NullPointerException.class,
				() -> onlineCRLSource.getRevocationToken(goodCa, rootCa));
		assertEquals("DataLoader is not provided !", exception.getMessage());
	}

}
