/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.crl;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.junit.Test;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateSource;

/**
 * This class tests the revocation status against a CRL of the belgian citizen's
 * certificate. <code>CRLCertificateVerifier</code> is used.</br> Used
 * classes:</br> <li><code>MockCRLSource</code></li> <li>
 * <code>CRLCertificateVerifier</code></li>
 *
 * @version $Revision$ - $Date$
 */
public class CommonCRLSourceTest {

	@Test
	public void isValidCRL() throws Exception {
		String crlFile = "/crl/belgium2.crl";
		final MockCRLSource mockCRLSource = new MockCRLSource(getClass().getResourceAsStream(crlFile));
		final X509CRL x509CRL = DSSUtils.loadCRL(getClass().getResourceAsStream(crlFile));

		final CertificateToken issuerToken = getCertificateToken();

		CRLValidity validCRL = mockCRLSource.isValidCRL(x509CRL, issuerToken);
		assertNotNull(validCRL);
		assertTrue(validCRL.isValid());
		assertTrue(validCRL.isIssuerX509PrincipalMatches());
	}

	@Test
	public void checkCriticalExtensions() throws Exception {
		String crlFile = "/crl/pt_crl_with_critical_extension.crl";
		final MockCRLSource mockCRLSource = new MockCRLSource(getClass().getResourceAsStream(crlFile));
		final X509CRL x509CRL = DSSUtils.loadCRL(getClass().getResourceAsStream(crlFile));

		final CertificateToken issuerToken = getCertificateToken();

		CRLValidity validCRL = mockCRLSource.isValidCRL(x509CRL, issuerToken);
		assertNotNull(validCRL);
		assertFalse(validCRL.isUnknownCriticalExtension());
		assertFalse(validCRL.isIssuerX509PrincipalMatches());
		assertFalse(validCRL.isValid());
	}

	private CertificateToken getCertificateToken() {
		final X509Certificate citizen = DSSUtils.loadCertificate("/citizen_ca.cer");
		assertNotNull(citizen);
		final X509Certificate belgium = DSSUtils.loadCertificate("/belgiumrs2.crt");
		assertNotNull(belgium);

		final CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
		final CertificateToken certificateToken = commonCertificateSource.addCertificate(citizen);
		final CertificateToken issuerToken = commonCertificateSource.addCertificate(belgium);
		final boolean signedBy = certificateToken.isSignedBy(issuerToken);

		// We associate the issuer certificate
		assertTrue(signedBy);
		return issuerToken;
	}
}
