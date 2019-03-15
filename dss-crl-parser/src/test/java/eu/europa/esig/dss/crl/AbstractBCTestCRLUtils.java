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
package eu.europa.esig.dss.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.x509.CertificateToken;

public abstract class AbstractBCTestCRLUtils {

	private static CertificateFactory certificateFactory;

	@BeforeClass
	public static void init() {
		Security.addProvider(new BouncyCastleProvider());
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new DSSException("Unable to init the CertificateFactory", e);
		}
	}

	@AfterClass
	public static void reset() {
		Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

	@Test
	public void testPSSwithBouncyCastle() throws Exception {
		try (InputStream is = AbstractBCTestCRLUtils.class.getResourceAsStream("/d-trust_root_ca_1_2017.crl");
				InputStream isCer = AbstractBCTestCRLUtils.class.getResourceAsStream("/D-TRUST_Root_CA_1_2017.crt")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLValidity validity = CRLUtils.isValidCRL(is, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, validity.getSignatureAlgorithm());
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNull(validity.getExpiredCertsOnCRL());
			assertNotNull(validity.getIssuerToken());
			assertTrue(validity.isValid());
		}
	}

	protected CertificateToken loadCert(InputStream is) throws CertificateException {
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(is);
		return new CertificateToken(certificate);
	}

}
