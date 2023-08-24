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
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OnlineCRLSourceTest {

	private static final String alternative_url = "http://dss.nowina.lu/pki-factory/crl/root-ca.crl";
	private static final String wrong_url = "http://wrong.url";
	
	private static OnlineCRLSource onlineCRLSource;
	private static CommonsDataLoader dataLoader;

	private static CertificateToken goodUser;
	private static CertificateToken goodCa;
	private static CertificateToken rootCa;

	private static CertificateToken ed25519goodUser;
	private static CertificateToken ed25519goodCa;
	private static CertificateToken ed25519RootCa;

	@BeforeAll
	public static void init() {
		dataLoader = new CommonsDataLoader();

		goodUser = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/good-user.crt"));
		goodCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/good-ca.crt"));
		rootCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/root-ca.crt"));

		ed25519goodUser = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/Ed25519-good-user.crt"));
		ed25519goodCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/Ed25519-good-ca.crt"));
		ed25519RootCa = DSSUtils.loadCertificate(dataLoader.get("http://dss.nowina.lu/pki-factory/crt/Ed25519-root-ca.crt"));
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
	public void getRevocationTokenWithAlternateUrlTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Collections.singletonList(alternative_url)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));
		
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Collections.singletonList(alternative_url));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void getRevocationTokenWithWrongAlternateUrlTest() {
		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Collections.singletonList(wrong_url)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));

		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Collections.singletonList(wrong_url));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void timeoutTest() {
		dataLoader.setTimeoutResponse(1);

		Exception exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodUser, goodCa, Arrays.asList(wrong_url, alternative_url)));
		assertTrue(exception.getMessage().contains("Unable to retrieve CRL for certificate with Id '" + goodUser.getDSSIdAsString() + "'"));
		assertTrue(exception.getMessage().contains("Read timed out"));

		exception = assertThrows(DSSExternalResourceException.class,
				() -> onlineCRLSource.getRevocationToken(goodCa, rootCa, Arrays.asList(wrong_url, alternative_url)));
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
