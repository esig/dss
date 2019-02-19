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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import org.junit.Test;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.x509.CertificateToken;

public abstract class AbstractTestCRLUtils {

	private static final CertificateFactory certificateFactory;

	static {
		try {
			certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new DSSException("Platform does not support X509 certificate", e);
		}
	}

	@Test
	public void isValidCRL() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/belgium2.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/belgiumrs2.crt")) {
			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);
			assertNotNull(validCRL);
			assertNotNull(validCRL.getIssuerToken());
			assertNotNull(validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertTrue(validCRL.isIssuerX509PrincipalMatches());
			assertTrue(validCRL.isSignatureIntact());
			assertTrue(validCRL.isValid());
			assertTrue(validCRL.isCrlSignKeyUsage());
			assertFalse(validCRL.isUnknownCriticalExtension());
			assertEquals(certificateToken, validCRL.getIssuerToken());
			assertNull(validCRL.getSignatureInvalidityReason());
			assertNull(validCRL.getUrl());
		}
	}

	@Test
	public void isValidPEMCRL() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/belgium2.pem.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/belgiumrs2.crt")) {
			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);
			assertNotNull(validCRL);
			assertNotNull(validCRL.getIssuerToken());
			assertNotNull(validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertTrue(validCRL.isIssuerX509PrincipalMatches());
			assertTrue(validCRL.isSignatureIntact());
			assertTrue(validCRL.isValid());
			assertTrue(validCRL.isCrlSignKeyUsage());
			assertFalse(validCRL.isUnknownCriticalExtension());
			assertEquals(certificateToken, validCRL.getIssuerToken());
			assertNull(validCRL.getSignatureInvalidityReason());
			assertNull(validCRL.getUrl());
		}
	}

	@Test
	public void isValidCRLWrongCertificate() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/belgium2.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {
			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);
			assertNotNull(validCRL);
			assertNull(validCRL.getIssuerToken());
			assertNotNull(validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertFalse(validCRL.isIssuerX509PrincipalMatches());
			assertFalse(validCRL.isSignatureIntact());
			assertFalse(validCRL.isValid());
			assertNotNull(validCRL.getSignatureInvalidityReason());
		}
	}

	@Test
	public void testLTGRCA() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/LTGRCA.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SHA1, validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertNull(validCRL.getExpiredCertsOnCRL());

			assertFalse(validCRL.isIssuerX509PrincipalMatches());
			assertFalse(validCRL.isSignatureIntact());
			assertFalse(validCRL.isValid());
		}
	}

	@Test
	public void testGetExpiredCertsOnCRL() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/crl_with_expiredCertsOnCRL_extension.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SHA256, validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertNotNull(validCRL.getExpiredCertsOnCRL());
			assertNotNull(validCRL.getUrl());

			assertFalse(validCRL.isIssuerX509PrincipalMatches());
			assertFalse(validCRL.isSignatureIntact());
			assertFalse(validCRL.isValid());
		}
	}

	@Test
	public void testGetExpiredCertsOnCRLUTCTime() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/crl-expiredCertsOnCRL-UTCTime.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity validCRL = CRLUtils.isValidCRL(is, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SHA256, validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertNull(validCRL.getExpiredCertsOnCRL()); // Ignored
			assertNull(validCRL.getUrl());

			assertFalse(validCRL.isIssuerX509PrincipalMatches());
			assertFalse(validCRL.isSignatureIntact());
			assertFalse(validCRL.isValid());
		}
	}

	@Test
	public void retrieveRevocation() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/http___crl.globalsign.com_gs_gspersonalsign2sha2g2.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLValidity validity = CRLUtils.isValidCRL(is, certificateToken);

			BigInteger serialNumber = new BigInteger("288350169419475868349393253038503091234");
			X509CRLEntry entry = CRLUtils.getRevocationInfo(validity, serialNumber);
			assertNotNull(entry);
			assertNotNull(entry.getRevocationDate());
			assertNull(entry.getRevocationReason());
			assertNotNull(entry.getSerialNumber());
			assertEquals(serialNumber, entry.getSerialNumber());

			serialNumber = new BigInteger("288350169419475868349393264025423631520");
			entry = CRLUtils.getRevocationInfo(validity, serialNumber);
			assertNotNull(entry);
			assertNotNull(entry.getRevocationDate());
			assertNull(entry.getRevocationReason());
			assertNotNull(entry.getSerialNumber());
			assertEquals(serialNumber, entry.getSerialNumber());

			serialNumber = new BigInteger("111111111111111111111111111");
			entry = CRLUtils.getRevocationInfo(validity, serialNumber);
			assertNull(entry);
		}
	}

	@Test
	public void testARLFile() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/notaires2020.arl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLValidity validity = CRLUtils.isValidCRL(is, certificateToken);
			assertNotNull(validity);
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNotNull(validity.getSignatureAlgorithm());
		}
	}

	@Test(expected = Exception.class)
	public void notACRL() throws Exception {
		try (InputStream is = new ByteArrayInputStream(new byte[] { 1, 2, 3 });
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLUtils.isValidCRL(is, certificateToken);
		}
	}

	// @Ignore
	@Test
	public void testHugeCRL() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/esteid2011.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/ESTEID-SK_2011.der.crt")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLValidity validity = CRLUtils.isValidCRL(is, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SHA256, validity.getSignatureAlgorithm());
			assertNotNull(validity.getIssuerToken());
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNull(validity.getExpiredCertsOnCRL());
			assertTrue(validity.isValid());

			BigInteger serialNumber = new BigInteger("1111111111111111111");
			assertNull(CRLUtils.getRevocationInfo(validity, serialNumber));
		}
	}

	@Test
	public void testRealNot() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/realts2019.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/realts2019.crt")) {
			CertificateToken certificateToken = loadCert(isCer);
			CRLValidity wrongIssuerCRL = CRLUtils.isValidCRL(is, certificateToken);

			assertNotNull(wrongIssuerCRL);
			assertNull(wrongIssuerCRL.getIssuerToken());
			assertNotNull(wrongIssuerCRL.getThisUpdate());
			assertNotNull(wrongIssuerCRL.getNextUpdate());
			assertTrue(wrongIssuerCRL.isIssuerX509PrincipalMatches());
			assertNotNull(wrongIssuerCRL.getSignatureInvalidityReason());
			assertFalse(wrongIssuerCRL.isValid());
			assertEquals(SignatureAlgorithm.RSA_SHA256, wrongIssuerCRL.getSignatureAlgorithm());
		}
	}

	protected CertificateToken loadCert(InputStream is) throws CertificateException {
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(is);
		return new CertificateToken(certificate);
	}

}
