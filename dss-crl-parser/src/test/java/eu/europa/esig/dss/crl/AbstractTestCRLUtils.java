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

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractTestCRLUtils extends AbstractCRLParserTestUtils {

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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
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
	public void testUA() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/CA-5358AA45-Full.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/CA-Justice-ECDSA-261217.cer")) {
			CertificateToken certificateToken = loadCert(isCer);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertNotNull(validCRL.getIssuerToken());
			assertEquals(SignatureAlgorithm.ECDSA_SHA256, validCRL.getSignatureAlgorithm());
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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertNotNull(validCRL.getSignatureAlgorithm());
			assertNotNull(validCRL.getThisUpdate());
			assertNotNull(validCRL.getNextUpdate());
			assertTrue(validCRL.isIssuerX509PrincipalMatches());
			assertTrue(validCRL.isSignatureIntact());
			assertNotNull(validCRL.getIssuerToken());
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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

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
	public void derVsPemEncodedTest() throws Exception {
		try (InputStream isDer = AbstractTestCRLUtils.class.getResourceAsStream("/DSS-2039/crl.der");
				InputStream isPem = AbstractTestCRLUtils.class.getResourceAsStream("/DSS-2039/crl.pem");
				InputStream isCert = AbstractTestCRLUtils.class.getResourceAsStream("/DSS-2039/cert.pem");
				InputStream isCA = AbstractTestCRLUtils.class.getResourceAsStream("/DSS-2039/ca.pem") ) {

			CertificateToken cert = loadCert(isCert);
			CertificateToken ca = loadCert(isCA);
			
			CRLBinary crlBinaryDER = CRLUtils.buildCRLBinary(toByteArray(isDer));
			CRLValidity crlDER = CRLUtils.buildCRLValidity(crlBinaryDER, ca);
			
			CRLBinary crlBinaryPEM = CRLUtils.buildCRLBinary(toByteArray(isPem));
			CRLValidity crlPEM = CRLUtils.buildCRLValidity(crlBinaryPEM, ca);
			
			assertArrayEquals(crlDER.getDerEncoded(), crlPEM.getDerEncoded());
			
			X509CRLEntry revocationInfoDER = CRLUtils.getRevocationInfo(crlDER, cert.getSerialNumber());
			X509CRLEntry revocationInfoPEM = CRLUtils.getRevocationInfo(crlPEM, cert.getSerialNumber());
			assertEquals(revocationInfoDER, revocationInfoPEM);
		}
	}

	@Test
	public void retrieveRevocation() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/http___crl.globalsign.com_gs_gspersonalsign2sha2g2.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

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

			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validity);
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNotNull(validity.getSignatureAlgorithm());
		}
	}

	// @Ignore
	@Test
	public void testHugeCRL() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/esteid2011.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/ESTEID-SK_2011.der.crt")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

			assertEquals(SignatureAlgorithm.RSA_SHA256, validity.getSignatureAlgorithm());
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNull(validity.getExpiredCertsOnCRL());
			assertNotNull(validity.getIssuerToken());
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
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity wrongIssuerCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

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

	@Test
	public void testECDSA() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/EE-GovCA2018.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/EE-GovCA2018.pem.crt")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

			assertEquals(SignatureAlgorithm.ECDSA_SHA512, validity.getSignatureAlgorithm());
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNull(validity.getExpiredCertsOnCRL());
			assertNotNull(validity.getIssuerToken());
			assertTrue(validity.isValid());
		}
	}

	@Test
	public void testECDSAwithRSACert() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/EE-GovCA2018.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/citizen_ca.cer")) {

			CertificateToken certificateToken = loadCert(isCer);

			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(is));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);

			assertEquals(SignatureAlgorithm.ECDSA_SHA512, validity.getSignatureAlgorithm());
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertNull(validity.getExpiredCertsOnCRL());
			assertNull(validity.getIssuerToken());
			assertFalse(validity.isValid());
		}
	}

	@Test
	@DisabledForJreRange(min = JRE.JAVA_16)
	public void testPSSwithoutBouncyCastle() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/d-trust_root_ca_1_2017.crl");
				InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/D-TRUST_Root_CA_1_2017.crt")) {
			Exception exception = assertThrows(IllegalArgumentException.class, () -> loadCert(isCer));
			assertEquals("Unable to initialize PSS", exception.getMessage());
		}
	}

	@Test
	@DisabledForJreRange(max = JRE.JAVA_15)
	public void testPSSwithoutBouncyCastleBeforeJDK16() throws Exception {
		try (InputStream is = AbstractTestCRLUtils.class.getResourceAsStream("/d-trust_root_ca_1_2017.crl");
			 InputStream isCer = AbstractTestCRLUtils.class.getResourceAsStream("/D-TRUST_Root_CA_1_2017.crt")) {
			assertNotNull(loadCert(isCer));
		}
	}

	@Test
	public void incompleteCRL() throws Exception {
		try (InputStream is = new ByteArrayInputStream(new byte[] { 1, 2, 3 })) {
			byte[] byteArray = toByteArray(is);
			Exception exception = assertThrows(DSSException.class, () -> CRLUtils.buildCRLBinary(byteArray));
			assertTrue(exception.getMessage().contains("Unable to load CRL."));
		}
	}

	@Test
	public void rsaSHA1() throws Exception {
		String crlB64 = "MIIBbTBXMA0GCSqGSIb3DQEBBQUAMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EyFw0xNDA3MDExMTAwMDBaFw0xNTAxMzExMTAwMDBaMA0GCSqGSIb3DQEBBQUAA4IBAQClCqf+EHb/ZafCIrRXdEmIOrHV0fFYfIbLEWUhMLIDBdNgcDeKjUOB6dc3WnxfyuE4RzndBbZA1dlDv7wEX8sxaGzAdER166uDS/CF7wwVz8voDq+ju5xopN01Vy7FNcCA43IpnZal9HPIQfb2EyrfNu5hQal7WiKE7q8PSch1vBlB9h8NbyIfnyPiHZ7A0B6MPJBqSCFwgGm+YZB/4DQssOVui0+kBT19uUBjTG0QEe7dLxZTBEgBowq5axv93QBXe0j+xOXZ97tlU2iJ51bsLY3E134ziMV6hKPsBw6ARMq/BF64P6axLIUOqdCRaYoMu2ekfYSoFuaM3l2o79aw";
		String certB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		try (InputStream crlIS = new ByteArrayInputStream(Base64.getDecoder().decode(crlB64));
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertTrue(validCRL.isSignatureIntact());
			assertTrue(validCRL.isValid());
			assertEquals(SignatureAlgorithm.RSA_SHA1, validCRL.getSignatureAlgorithm());
		}
	}

	@Test
	public void rsaSHA1bis() throws Exception {
		String crlB64 = "MIICbTBXMA0GCSqGSIb3DQEBBQUAMCgxCzAJBgNVBAYTAkJFMRkwFwYDVQQDExBCZWxnaXVtIFJvb3QgQ0EzFw0xNDA3MDExMTAwMDBaFw0xNTAxMzExMTAwMDBaMA0GCSqGSIb3DQEBBQUAA4ICAQBgfKMetb6Qy9Jb06wIKEvHAOChVVm9rONBFUyaV2YEgtJFON+RosigKDhgTrS/Q2Ja6ZeQQl65PxxU63HzkgHtaZaS4MmFs6uIr58gJFyer4SDT/6YizwajlNFtuGvzauuxjA4XpfPd42xpPg4rrh6+7chEJ05kxJoPR5VWxmdMHQ3ne9AAtczV8DuVZsFD3eMdaxKBV0iFe9bBqy5jGaaZVJVbMKEB7kzAhNXOxuoYnXrsYP0w3D5IXj5EUeuWyg1GAzQ9lf0lqzax+2VtR89O/EwVzgrTggqLt/G3jNz13Z9LxSLGg0CaSAcjEGscqVpEgiZO9ZR4hOt/d1Fb+h09uYhFp+og2oQBT43CJlt7q1WC/L4BhIYg10YJPC69hgP3mqwbJr4R7/6FaJhBwsgw6NxrmgoefNb9G8bT2w4/vV8W4kkFEVa38YkWSmuyTgJU40IYeKGEIamXnbmWki6zXPYRApo873qRd/FN2iTU9781bSgZ/QOi2Z98ZJAEwcYRgGtfpTGsCvA8Fg4DaVReJfEGog1p22XQefO2cLJCcXCdibFReQOB+TpFfBltdoF8MFGZ1qc1McSfpr1C3U80IyYmc+kP/EZIQlZKEoGg3B81j9X2Y+6uBWlkTa3Ki4VLsItHNc4FRVsqQ+X2swA8iPc6pEURDBcBbA3pKaQSA==";
		String certB64 = "MIIFjjCCA3agAwIBAgIIOyEC3pZbHakwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTMwHhcNMTMwNjI2MTIwMDAwWhcNMjgwMTI4MTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKjyAZ2Lg8kHoIX7JLc3BeZ1Tzy9MEv7Bnr59xcJezc/xJJdO4V3bwMltKFfNvqsQ5H/GQADFJ0GmTLLPDI5AoeUjBubRZ9hwruUuQ11+vhtoVhuEuZUxofEIU2yJtiSOONwpo/GIb9C4YZ5h+7ltDpC3MvsFyyordpzgwqSHvFwTCmls5SpU05UbF7ZVPcfVf24A5IgHLpZTgQfAvnzPlm++eJY+sNoNzTBoe6iZphmPbxuPNcJ6slV8qMQQk50/g+KmoPpHX4AvoTr4/7TMTvuK8jS1dEn+fdVKdx9qo9ZZRHFW/TXEn5SrNUu99xhzlE/WBurrVwFoKCWCjmO0CnekJlw0NTr3HBTG5D4AiDjNFUYaIcGJk/ha9rzHzY+WpGdoFZxhbP83ZGeoqkgBr8UzfOFCY8cyUN2db6hpIaK6Nuoho6QWnn+TSNh5Hjui5miqpGxS73gYlT2Qww16h8gFTJQ49fiS+QHlwRw5cqFuqfFLE3nFFF9KIamS4TSe7T4dNGY2VbHzpaGVT4wy+fl7gWsfaUkvhM4b00DzgDiJ9BHiKytNLmzoa3Sneij/CKur0dJ5OdMiAqUpSd0Oe8pdIbmQm1oP5cjckiQjxx7+vSxWtacpGowWK8+7oEsYc+7fLt3GD6q/O5Xi440Pd/sFJmfqRf3C1PPMdBqXcwjAgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAoBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUuLxsAI9bGYWdJQGc8BncQI7QOCswEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFLi8bACPWxmFnSUBnPAZ3ECO0DgrMA0GCSqGSIb3DQEBBQUAA4ICAQBFYjv/mKX+VcyxEacckgx4L8XvFkIFPXzjEnDnAtCCkROU/k5n1jjVK+ODOn+Q4kJg6Nd7K47+zTXcrSe1tB2gVMsyaCN9scy4phLX1qT48sThCjUtooxfIoRycpdlf14HcUPCYlASTCapZU0MnAbzfpzxm49Ik/A2JWxAhxXVRHwOu3TMGiQ4W/VyVawxjwQMO8TneBDombmkXsI9bI0OxWUh2A5dKlqu0sYvE0dz8xDxr9ZkmZqYcPIKizCZlaP1ZsSlCi5S31gn3EUP+fd21q6ZXgU+50/qgoh/0UUaHRpedPQBES/FYc2IQZ2XjhmeTwM+9Lk7tnzHeHp3dgCoOfceyPUaVkWiXMWcNAvvkDVELvXfJpRxwcRfS5Ks5oafOfj81RzGUbmpwl2usOeCRwdWE8gPvbfWNQQC8MJquDl5HdeuzUesTXUqXeEkyAOo6YnF3g0qGcLI9NXusji1egRUZ7B4XCvG52lTB7Wgd/wVFzS3f4mAmYTGJXH+N/lrBBGKuTJ5XncJaliFUKxGP6VmNyaaLUF5IlTqC9CGHPLSXOgDokt2G9pNwFm2t7AcpwAmegkMNpgcgTd+qk2yljEaT8wf953jUAFedbpN3tX/3i+uvHOOmWjQOxJg2lVKkC+bkWa2FrTBDdrlEWVaLrY+M+xeIctrC0WnP7u4xg==";

		try (InputStream crlIS = new ByteArrayInputStream(Base64.getDecoder().decode(crlB64));
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertTrue(validCRL.isSignatureIntact());
			assertTrue(validCRL.isValid());
			assertEquals(SignatureAlgorithm.RSA_SHA1, validCRL.getSignatureAlgorithm());
		}
	}

	@Test
	public void rsaSHA256() throws Exception {
		String crlB64 = "MIIDbjCCAlYCAQEwDQYJKoZIhvcNAQELBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIXDTE5MDEwMTExMDAwMFoXDTE5MDczMTExMDAwMFowggHHMCECEDW3OvEPBB82u9j/4UlnHXcXDTE2MDIxNTExMDAwMFowIQIQL1fHogsVxmfMBka5q4uzaRcNMTYwMjE1MTEwMDAwWjAhAhBEWWaaO6WPpV7s98GLjiefFw0xNjAyMTUxMTAwMDBaMCECEC4s3llxVj+aWTyP3S3Pj1UXDTE2MDIxNTExMDAwMFowIQIQTUVQV0lyPD0vIT44fF4uZBcNMTYwMjE1MTEwMDAwWjAhAhBUFJ/4idyxMHdFlLgoUIk9Fw0xNjAyMTUxMTAwMDBaMCECEFVLWoTsL75iRcJb5hg2T+cXDTE2MDIxNTExMDAwMFowIQIQeLumDUO40KwnecZLJxFM2BcNMTYwMjE1MTEwMDAwWjAhAhBl4waBnJUE6bod+GIj6MTPFw0xNjAyMTUxMTAwMDBaMCECEGpqd0JtRXkuLFZHNlEicWUXDTE2MDIxNTExMDAwMFowIQIQRH7WhshwXRK6f0VfOfjXgRcNMTYwMjE1MTEwMDAwWjAhAhB+uPmNO6oGdDh+WM+9VTcoFw0xNjAyMTUxMTAwMDBaMCECEEiVlv1B8vdvwaYrBfEM2YQXDTE2MDIxNTExMDAwMFqgLzAtMAoGA1UdFAQDAgEEMB8GA1UdIwQYMBaAFIWK6/TFu74OWQOU3taAARXjEJw5MA0GCSqGSIb3DQEBCwUAA4IBAQB+GEV0MQQB+iPKDO9hGAGMjIEILK6m3bTdDNDBchQPoCSFTpNbKglq0c4NnAh/nUYTW8i0vENnPzVuL90xV7K36lCjaZDQOjSPSwNDLEgCK4ONK7ReW0tbFPTkTiKYd59uGIm11x5/KtHxLCX44uctoN1ZkQNnmRP2HPs6Djhtt3LTAD1oZ/YC0tQdsZUGfaFDcdgCor5hyrOdgHh+quMapZ7Wm1J1eSzJQrxADaFWq3FPsNKLlqtFZQP9t6nrdVHyUktHv9Dyf+Xjm68nDya7rGW7n/LvCLJMYzcdGd1t8podI+VcPolUKdUuyfS5S98XunmyhFtUHZbtqQgQmuh/";
		String certB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		try (InputStream crlIS = new ByteArrayInputStream(Base64.getDecoder().decode(crlB64));
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertTrue(validCRL.isSignatureIntact());
			assertTrue(validCRL.isValid());
			assertEquals(SignatureAlgorithm.RSA_SHA256, validCRL.getSignatureAlgorithm());
		}
	}

	@Test
	public void testPE() throws Exception {
		String certB64 = "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";

		try (InputStream crlIS = AbstractTestCRLUtils.class.getResourceAsStream("/hgcaclass2.crl");
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validCRL = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validCRL);
			assertTrue(validCRL.isSignatureIntact());
			assertFalse(validCRL.isValid());
			assertFalse(validCRL.isCrlSignKeyUsage());
			assertFalse(certificateToken.checkKeyUsage(KeyUsageBit.CRL_SIGN));
			assertEquals(SignatureAlgorithm.RSA_SHA256, validCRL.getSignatureAlgorithm());
		}
	}

	@Test
	public void loopIssue() throws Exception {
		String certB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		try (InputStream crlIS = AbstractTestCRLUtils.class.getResourceAsStream("/infinite-loop.crl");
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {

			byte[] base64 = toByteArray(crlIS);

			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(Base64.getDecoder().decode(base64));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validity);
			assertNotNull(validity.getThisUpdate());
			assertNotNull(validity.getNextUpdate());
			assertEquals(SignatureAlgorithm.RSA_SHA256, validity.getSignatureAlgorithm());

			// wrong certificate
			assertFalse(validity.isValid());

			assertNull(CRLUtils.getRevocationInfo(validity, BigInteger.ZERO));

			// latest entry
			assertNotNull(CRLUtils.getRevocationInfo(validity, new BigInteger("1938296")));
		}
	}

	@Test
	public void loopIssue2() throws Exception {
		String crlB64 = "MIIDDjCCAfYCAQEwDQYJKoZIhvcNAQELBQAwgfsxCzAJBgNVBAYTAkNaMRcwFQYDVQQKDA5lSWRlbnRpdHkgYS5zLjE8MDoGA1UECwwzQWtyZWRpdG92YW7DvSBwb3NreXRvdmF0ZWwgY2VydGlmaWthxI1uw61jaCBzbHXFvmViMS8wLQYDVQQHDCZWaW5vaHJhZHNrw6EgMTg0LzIzOTYsIDEzMCAwMCwgUHJhaGEgMzFkMGIGA1UEAwxbQUNBZUlEMiAtIFF1YWxpZmllZCBSb290IENlcnRpZmljYXRlIChrdmFsaWZpa292YW7DvSBzeXN0w6ltb3bDvSBjZXJ0aWZpa8OhdCBrb8WZZW5vdsOpIENBKRcNMTYwNDIyMjAzMDIzWhcNMTYwNjIyMjAzMDIzWjCBlDAjAgQI1bqvFw0xNjAyMjIxNTEzNDNaMAwwCgYDVR0VBAMKAQQwIwIECug4YBcNMTAwNTI0MDkwMzMwWjAMMAoGA1UdFQQDCgEEMCMCBB1MvkgXDTE2MDQyMjIwMjk1OFowDDAKBgNVHRUEAwoBBTAjAgRDCeIEFw0xNjAyMjIxNTE0MDNaMAwwCgYDVR0VBAMKAQSgLzAtMB8GA1UdIwQYMBaAFJX+I1AvymNw08DBJRIhcsW65p5dMAoGA1UdFAQDAgFiMA0GCSqGSIb3DQEBCwUAA4IBAQBmyB+j4DWBsJok3NrC/fbV6iGSmnFClD2IH1sHzn1tp5MO2Q1LYRGI687Fg1Sw7z3aWxU+QbFvlJC74YyzkLTJ/Di0kxpOgTFx/6qcwBuaZp0Dx7cobjmuX7M3t0aMcg0awSQZxP0K5VkilzyuNgY+7MPnWgi5jbDDSKF3suDpfBex33zhyUgfpUew4jBX01NeoabimZwFJvRhAeb1J+iJMDsZSB5Kxxhn0kxU/czjedzQOl3wYda/GHdckyduya5Q7TAtuPLYwVV9U1/QD5dffjaG7uS5Spk7o7SWWnSCOgcDaPWzGGURRTyzeDZjacpwbKlJp27QwK7KH7430yJuDQo=";
		String certB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		try (InputStream crlIS = new ByteArrayInputStream(Base64.getDecoder().decode(crlB64));
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validity);

			// wrong certificate
			assertFalse(validity.isValid());

			assertNull(CRLUtils.getRevocationInfo(validity, BigInteger.ZERO));
			assertNotNull(CRLUtils.getRevocationInfo(validity, new BigInteger("1124721156")));
		}
	}

	@Test
	public void noRevoc() throws Exception {
		String crlB64 = "MIICYjCCAUoCAQEwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQ1oxLDAqBgNVBAoMI8SMZXNrw6EgcG/FoXRhLCBzLnAuIFtJxIwgNDcxMTQ5ODNdMR4wHAYDVQQDExVQb3N0U2lnbnVtIFJvb3QgUUNBIDIXDTE2MDMyMjA4MDE0N1oXDTE3MDMyMjA4MDY0N1owIzAhAgIAmhcNMTMxMjEwMDgwOTM4WjAMMAoGA1UdFQQDCgEEoIGVMIGSMAoGA1UdFAQDAgEJMIGDBgNVHSMEfDB6gBQVKYzFRWmruLPD6v5LuDHY3PDndqFfpF0wWzELMAkGA1UEBhMCQ1oxLDAqBgNVBAoMI8SMZXNrw6EgcG/FoXRhLCBzLnAuIFtJxIwgNDcxMTQ5ODNdMR4wHAYDVQQDExVQb3N0U2lnbnVtIFJvb3QgUUNBIDKCAWQwDQYJKoZIhvcNAQELBQADggEBAJJgcYoG12xSqVpU9RKa7BcyjFVvOcnJQnoLfAlfoRvruQ3+9yKHc2g9VwxW29/+EOAexCu8wBB3dKb8buHfR75u6qdmxz9au0992/gTJYo6lZa1DBN+y45gR9ypw5RtkjYpwfdGP44ss/HjftUoaeYkXi6QXC6AsvXvm/DUQ3xVZt5OmZ5myL2SlOws4iAQMCrKT1HU3YCAB4DwtGzTcLskKiu6wiJzArzIk3AO3K0UFE6BrxpQiGxCsCQ3IdWy82CzLpmUG/FC7oO6GsJOftCxSo+S2ICxwHvfPEtL8r5C+msc8XYQPqO6l6kMTVRAD+iwhrLJBfc0W/2Y30lGtn0=";
		String certB64 = "MIIDjjCCAnagAwIBAgIIKv++n6Lw6YcwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTIwHhcNMDcxMDA0MTAwMDAwWhcNMjExMjE1MDgwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZzQh6S/3UPi790hqc/7bIYLS2X+an7mEoj39WN4IzGMhwWLQdC1i22bi+n9fzGhYJdld61IgDMqFNAn68KNaJ6x+HK92AQZw6nUHMXU5WfIp8MXW+2QbyM69odRr2nlL/zGsvU+40OHjPIltfsjFPekx40HopQcSZYtF3CiInaYNKJIT/e1wEYNm7hLHADBGXvmAYrXR5i3FVr/mZkIV/4L+HXmymvb82fqgxG0YjFnaKVn6w/Fa7yYd/vw2uaItgscf1YHewApDgglVrH1Tdjuk+bqv5WRi5j2Qsj1Yr6tSPwiRuhFA0m2kHwOI8w7QUmecFLTqG4flVSOmlGhHUCAwEAAaOBuzCBuDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zBCBgNVHSAEOzA5MDcGBWA4CQEBMC4wLAYIKwYBBQUHAgEWIGh0dHA6Ly9yZXBvc2l0b3J5LmVpZC5iZWxnaXVtLmJlMB0GA1UdDgQWBBSFiuv0xbu+DlkDlN7WgAEV4xCcOTARBglghkgBhvhCAQEEBAMCAAcwHwYDVR0jBBgwFoAUhYrr9MW7vg5ZA5Te1oABFeMQnDkwDQYJKoZIhvcNAQEFBQADggEBAFHYhd27V2/MoGy1oyCcUwnzSgEMdL8rs5qauhjyC4isHLMzr87lEwEnkoRYmhC598wUkmt0FoqW6FHvv/pKJaeJtmMrXZRY0c8RcrYeuTlBFk0pvDVTC9rejg7NqZV3JcqUWumyaa7YwBO+mPyWnIR/VRPmPIfjvCCkpDZoa01gZhz5v6yAlGYuuUGK02XThIAC71AdXkbc98m6tTR8KvPG2F9fVJ3bTc0R5/0UAoNmXsimABKgX77OFP67H6dh96tK8QYUn8pJQsKpvO2FsauBQeYNxUJpU4c5nUwfAA4+Bw11V0SoU7Q2dmSZ3G7rPUZuFF1eR1ONeE3gJ7uOhXY=";

		try (InputStream crlIS = new ByteArrayInputStream(Base64.getDecoder().decode(crlB64));
				InputStream certIS = new ByteArrayInputStream(Base64.getDecoder().decode(certB64))) {
			CertificateToken certificateToken = loadCert(certIS);
			CRLBinary crlBinary = CRLUtils.buildCRLBinary(toByteArray(crlIS));
			CRLValidity validity = CRLUtils.buildCRLValidity(crlBinary, certificateToken);
			assertNotNull(validity);

			// wrong certificate
			assertFalse(validity.isValid());

			assertNull(CRLUtils.getRevocationInfo(validity, BigInteger.ZERO));
		}
	}

	protected CertificateToken loadCert(InputStream is) throws CertificateException {
		X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(is);
		return new CertificateToken(certificate);
	}

}
