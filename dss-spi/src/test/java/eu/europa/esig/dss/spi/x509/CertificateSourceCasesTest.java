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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Arrays;

import static java.time.Duration.ofMillis;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeout;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateSourceCasesTest {

	@Test
	public void sameSubjectDifferentKeys() {

		// 2 certs : same subject + different keypairs
		CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEljCCA36gAwIBAgIUZ9JgBKo5Fny+mN5lhd+Pj3EzsjkwDQYJKoZIhvcNAQEFBQAwbjELMAkGA1UEBhMCUEwxLjAsBgNVBAoMJU1pbmlzdGVyIHdsYXNjaXd5IGRvIHNwcmF3IGdvc3BvZGFya2kxLzAtBgNVBAMMJk5hcm9kb3dlIENlbnRydW0gQ2VydHlmaWthY2ppIChOQ0NlcnQpMB4XDTExMTIwOTE0MzAxNFoXDTE2MTExNzIzNTk1OVowczELMAkGA1UEBhMCUEwxKDAmBgNVBAoMH0tyYWpvd2EgSXpiYSBSb3psaWN6ZW5pb3dhIFMuQS4xJDAiBgNVBAMMG0NPUEUgU1pBRklSIC0gS3dhbGlmaWtvd2FueTEUMBIGA1UEBRMLTnIgd3Bpc3U6IDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/Ak7VI05c+hGmL60crMCeG1Mj2U0qsK0cY2Hfb2Q8UKVfsZ94amI7zqo6Kuhuniqvgk0z7T+gZDyz1bCD+133MMLRZtno4/nWipeMSEweuMXFGivC+pksTcrtv2Z9cE8SyP8f5d1OEzisJ5ypP7sSbRQbr1jm4kYnT66ZBMZdGgSR2dMm4GyzSIxes4SYFhoBh7gs2hm3EzksnkY/UYqC0TlTA8gStS8bKb2hveWLpNK4kpT6V6bLk8I5rgKekjbkCFal/PPyE/VlhgCNwgFX77B9ugKKg0hGy05dAuBMx5qChRZMTv/U434agLjym4CD+FNnvCyS8Wo5/G0rmJwxAgMBAAGjggElMIIBITAPBgNVHRMBAf8EBTADAQH/MIGrBgNVHSMEgaMwgaCAFFk0DPt950UBb8lwlsJOBvgPgUP2oXKkcDBuMQswCQYDVQQGEwJQTDEuMCwGA1UECgwlTWluaXN0ZXIgd2xhc2Npd3kgZG8gc3ByYXcgZ29zcG9kYXJraTEvMC0GA1UEAwwmTmFyb2Rvd2UgQ2VudHJ1bSBDZXJ0eWZpa2FjamkgKE5DQ2VydCmCFGKnDQTDJLjUJ1bMP4Fr8usy7wcZMDEGA1UdIAEB/wQnMCUwIwYEVR0gADAbMBkGCCsGAQUFBwIBFg13d3cubmNjZXJ0LnBsMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQURX3Y1swqY/j9vX0AKlOm56reW0wwDQYJKoZIhvcNAQEFBQADggEBAKOO47YvgBH6dDgHW6FD0Hlk8ZYqTjH/ycENuZCPrvyDswp2nfKOZuMwpYdZ3+nj3QcGPZzvV8ezM1wzNJBh4Cx+YJcPGhnE09ilb89Q7XQlGocisac/T02E8a2q5EXcbT2HOCONswGnJVXm9dTu42v4cBXiRk+edtifclrZedXek/zS6sQ9WAcoe7ANnRMgX08YhawN7l5EyzKh/tf/3rI9gU7iLd3hQMZh2gFcKCWgWKcRZHNs+o4DBcQiLxR1DtO/lutO+huj9dCzI4ZitljNjFSZtOCo1k4C/Z4XGtPB5uSyNuc60+8gVcSi4eqVEhV6uiqs95SYeyMhk62FZms=");
		CertificateToken c2 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEljCCA36gAwIBAgIUUK+3ZNp1763rDwjSam5zCOryw+IwDQYJKoZIhvcNAQEFBQAwbjELMAkGA1UEBhMCUEwxLjAsBgNVBAoMJU1pbmlzdGVyIHdsYXNjaXd5IGRvIHNwcmF3IGdvc3BvZGFya2kxLzAtBgNVBAMMJk5hcm9kb3dlIENlbnRydW0gQ2VydHlmaWthY2ppIChOQ0NlcnQpMB4XDTE0MDgxODA5MDkxOVoXDTE5MDgwNjIzNTk1OVowczELMAkGA1UEBhMCUEwxKDAmBgNVBAoMH0tyYWpvd2EgSXpiYSBSb3psaWN6ZW5pb3dhIFMuQS4xJDAiBgNVBAMMG0NPUEUgU1pBRklSIC0gS3dhbGlmaWtvd2FueTEUMBIGA1UEBRMLTnIgd3Bpc3U6IDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCGPM9MAhHt9Hh+E5cTUPnhcGIzXHZYgMJo+n8y9L85zbYRf12kE5FOQctjghAre9awm0pqjpZial8J6tGRwWpAcT55xuZKKQCta1YZFMX3cCWQKSkYEA5Y3VtJKYovEk1OTNDzZ6bFxq+GfoWRtJV8bThkX4cW3YVMyf4YRWgWaQyOwipbmkQ2WkD9Dvr6fIwObT+Rj61cWCQ/BGw4UiiJ5rdmwDokxJ+ptnQsM2N2Ig3iJ99m3kDMOR+cIj+IqxKp74pfR3BNeSPdNTzb4AY4clNqevHGcxv9iAlMZ5LZI//2AlB0mLshGRDTqzyb6LbsG2FupXwC2LMiqC9LdgUvAgMBAAGjggElMIIBITAPBgNVHRMBAf8EBTADAQH/MIGrBgNVHSMEgaMwgaCAFFk0DPt950UBb8lwlsJOBvgPgUP2oXKkcDBuMQswCQYDVQQGEwJQTDEuMCwGA1UECgwlTWluaXN0ZXIgd2xhc2Npd3kgZG8gc3ByYXcgZ29zcG9kYXJraTEvMC0GA1UEAwwmTmFyb2Rvd2UgQ2VudHJ1bSBDZXJ0eWZpa2FjamkgKE5DQ2VydCmCFGKnDQTDJLjUJ1bMP4Fr8usy7wcZMDEGA1UdIAEB/wQnMCUwIwYEVR0gADAbMBkGCCsGAQUFBwIBFg13d3cubmNjZXJ0LnBsMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUzEEqdpguSnoZ2pE239h/OT/Uwq4wDQYJKoZIhvcNAQEFBQADggEBADrUarpHf0nRoPqoNflKVnT/0xA9OPPHn+2Z48klX0FudPYtF1CfKIElCpQ75maEfbb41qLj+Ers8gpex46svELiNLT75M1ruSRD6+OD/Qsyrk9yxjpboPjlwuJDLQCrIfz+uKY+kjd/7FumzK7WPEkQqfYN6xwG/ik1RtvEH98jBShI1DiMGCRz6ERqDpaG+i6RS+cIjV3ccx/rWsJ/3lx6aUqL8ez2Q4wpVEAJ4/hYg9XroT06dWJWqBHiQZWCAR5Heyb6ykxD/eTI/TKnDYSe7ZkT0KtoQVV3xo0N5Q4mkRo4Zhj39nMppzhX8Ul5BxYa2niWtBdlWj7fVli7Bvs=");

		CommonTrustedCertificateSource ctcs = new CommonTrustedCertificateSource();
		ctcs.addCertificate(c1);

		CommonCertificateSource ccc = new CommonCertificateSource();
		ccc.addCertificate(c1);
		ccc.addCertificate(c2);
		ccc.addCertificate(c2);

		ListCertificateSource lcs = new ListCertificateSource(Arrays.asList(ctcs, ccc));

		assertEquals(2, lcs.getNumberOfCertificates());
		assertEquals(2, lcs.getNumberOfEntities());
		assertEquals(2, lcs.getBySubject(c1.getSubject()).size());

		assertEquals(1, lcs.getBySki(CertificateExtensionsUtils.getSubjectKeyIdentifier(c1).getSki()).size());
		assertEquals(1, lcs.getBySki(CertificateExtensionsUtils.getSubjectKeyIdentifier(c2).getSki()).size());
		assertEquals(1, lcs.getByPublicKey(c1.getPublicKey()).size());
		assertEquals(1, lcs.getByPublicKey(c2.getPublicKey()).size());

		assertTrue(lcs.isTrusted(c1));
		assertFalse(lcs.isTrusted(c2));

		assertEquals(2, lcs.getCertificateSourceType(c1).size());
		assertEquals(1, lcs.getCertificateSourceType(c2).size());
	}

	@Test
	public void crossCertificatesDifferentSubject() {

		// 2 cross certificates : same keypair + different subjects
		CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
		CertificateToken c2 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIHMTCCBhmgAwIBAgIBDzANBgkqhkiG9w0BAQUFADCBzjELMAkGA1UEBhMCSFUxETAPBgNVBAcTCEJ1ZGFwZXN0MR0wGwYDVQQKExRNQVYgSU5GT1JNQVRJS0EgS2Z0LjEYMBYGA1UECxMPUEtJIFNlcnZpY2VzIEJVMSAwHgYDVQQDDBdUcnVzdCZTaWduIFJvb3QgQ0EgdjEuMDEcMBoGA1UECRMTS3Jpc3p0aW5hIGtydC4gMzcvQTENMAsGA1UEERMEMTAxMjEkMCIGCSqGSIb3DQEJARYVaWNhQG1hdmluZm9ybWF0aWthLmh1MB4XDTA2MDYxMzAwMDAwMFoXDTEyMDkwNTAwMDAwMFowgdAxHDAaBgNVBAMME1RydXN0JlNpZ24gVFNBIHYyLjAxCzAJBgNVBAYTAkhVMREwDwYDVQQHDAhCdWRhcGVzdDEdMBsGA1UECgwUTUFWIElORk9STUFUSUtBIEtmdC4xGjAYBgNVBAsMEVBLSSBVemxldGkgZWd5c2VnMQ0wCwYDVQQRDAQxMDEyMRwwGgYDVQQJDBNLcmlzenRpbmEga3J0LiAzNy9hMSgwJgYJKoZIhvcNAQkBFhloaXRlbGVzQG1hdmluZm9ybWF0aWthLmh1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvjiELLKGYCv7mFmAcJPeF21gG1At2dlLM8rr5KxPlaIWfvNZ6CGCuzaIEFnHbl+DSLoQKwc6EFm6eXLiU/v2TEVZBtg7V8qgFOc7cXd+8lUo+Iog1anvid16Z3MLt+5xLY+orDNbeFR39nbATladtE/qpY5Etnq9S5xFqFMHAW0vQuF3JlIZ7BoTnLgxcetCWe3oJgQ/y4L9PbfYHCEJnUU2OwCCKT6hgPijKOaDS+4QpTFgXTl/lAl/poYXZuhaFpzPBp9zwXlxoGmgjD9IZld49c3NpGPabVrXQhF5yJyf9leA7PHDVwa7A6GRGU4nNpNo5eCjRd/PDgHC4Al9HwIDAQABo4IDFDCCAxAwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBkAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwNAYDVR0fBC0wKzApoCegJYYjaHR0cDovL2NybC50cnVzdC1zaWduLmh1L1Jvb3RDQS5jcmwwQgYIKwYBBQUHAQEENjA0MDIGCCsGAQUFBzAChiZodHRwOi8vd3d3LnRydXN0LXNpZ24uaHUvQ0EvcVJvb3QuY2VydDAfBgNVHSMEGDAWgBReNiAIT68CpHHO6+TwCn06Epb1QjAdBgNVHQ4EFgQUg82h+RMQhoEBG+FcRKBN9FxhNsswOgYIKwYBBQUHAQsELjAsMCoGCCsGAQUFBzADhh5odHRwczovL3RzYS50cnVzdC1zaWduLmh1OjEzMTgwggHgBgNVHSAEggHXMIIB0zCCAc8GCCsGAQQB9BQDMIIBwTA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5tYXZpbmZvcm1hdGlrYS5odS9jYS9kb3hfMS5odG0wggGGBggrBgEFBQcCAjCCAXgeggF0AEEAIAB0AGEAbgB1AHMAaQB0AHYAYQBuAHkAIABlAHIAdABlAGwAbQBlAHoAZQBzAGUAaABlAHoAIABlAHMAIABlAGwAZgBvAGcAYQBkAGEAcwBhAGgAbwB6ACAAYQAgAFMAegBvAGwAZwBhAGwAdABhAHQAbwAgAEgAUwB6AFMAegAtAGUAYgBlAG4AIABmAG8AZwBsAGEAbAB0AGEAawAgAHMAegBlAHIAaQBuAHQAIABrAGUAbABsACAAZQBsAGoAYQByAG4AaQAsACAAYQBtAGUAbAB5AGUAawAgAG0AZQBnAHQAYQBsAGEAbABoAGEAdABvAGEAawAgAGEAIABrAG8AdgBlAHQAawBlAHoAbwAgAGkAbgB0AGUAcgBuAGUAdABlAHMAIAB3AGUAYgAgAG8AbABkAGEAbABvAG4AOgAgAGgAdAB0AHAAOgAvAC8AdwB3AHcALgB0AHIAdQBzAHQALQBzAGkAZwBuAC4AaAB1MA0GCSqGSIb3DQEBBQUAA4IBAQCtAQg42z/hSomwtQMxfVdi0oZN/vFOlP6huYbeOyj53t9Rbt6OufbuWGdRmJgckvzOzai4wqm0EDPoX72eZjrQi5mbIqeA1cOgL2FNESGwMEVvOq7MfTtVuBB592dMtaFMzjiX9FnS2yDlyzkBNttDp5KaCPJg1/R65PvdU9Ix03L1wGRlkxiU6Ozd7+ldA/HTj6HUShGgbqc24ZjWi7NnfoUMz3azn9Qk7VNWxg7mMjdj4YXgtDZ++t0h+Y/sax3+IazOV9bAkA8/wmh7TuabluTLzRHyn5hlVgPxtqmV9xlgMU2H0QXaQOEDw39pzoUJ0r06P6J45HM4IxpJyah4");

		CommonCertificateSource ccc = new CommonCertificateSource();
		for (int i = 0; i < 1_000_000; i++) {
			ccc.addCertificate(c1);
			ccc.addCertificate(c2);
		}
		CommonTrustedCertificateSource ctcs = new CommonTrustedCertificateSource();
		ctcs.addCertificate(c2);
		
		ListCertificateSource lcs = new ListCertificateSource();
		lcs.add(ccc);
		lcs.add(ccc);
		lcs.add(ctcs);

		assertEquals(2, lcs.getNumberOfCertificates());
		assertEquals(1, lcs.getNumberOfEntities());
		assertEquals(1, lcs.getBySubject(c1.getSubject()).size());
		assertEquals(1, lcs.getBySubject(c2.getSubject()).size());

		assertEquals(2, lcs.getBySki(DSSASN1Utils.computeSkiFromCert(c1)).size());
		assertEquals(2, lcs.getBySki(DSSASN1Utils.computeSkiFromCert(c2)).size());
		assertEquals(2, lcs.getByPublicKey(c1.getPublicKey()).size());
		assertEquals(2, lcs.getByPublicKey(c2.getPublicKey()).size());

		assertFalse(lcs.isTrusted(c1));
		assertTrue(lcs.isTrusted(c2));

		assertEquals(0, lcs.getBySki(null).size());
		assertEquals(0, lcs.getBySki(new byte[] {}).size());
		assertEquals(0, lcs.getBySki(new byte[] { 1 }).size());
	}

	@Test
	public void crossCertificatesSameSubject() {

		// 2 cross certificates : same keypair + same subject
		CertificateToken c1 = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2.crt"));
		CertificateToken c2 = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrs2-signed.crt"));

		CommonCertificateSource ccc = new CommonCertificateSource();
		ccc.addCertificate(c1);
		ccc.addCertificate(c1);
		ccc.addCertificate(c2);
		ccc.addCertificate(c2);

		assertEquals(2, ccc.getNumberOfCertificates());
		assertEquals(1, ccc.getNumberOfEntities());
		assertEquals(2, ccc.getBySubject(c1.getSubject()).size());
		assertEquals(2, ccc.getBySubject(c2.getSubject()).size());
		assertEquals(2, ccc.getBySki(DSSASN1Utils.computeSkiFromCert(c1)).size());
		assertEquals(2, ccc.getBySki(DSSASN1Utils.computeSkiFromCert(c2)).size());

		assertFalse(ccc.isTrusted(c1));
		assertFalse(ccc.isTrusted(c2));

		CommonTrustedCertificateSource ctcs = new CommonTrustedCertificateSource();
		ctcs.addCertificate(c1);

		ListCertificateSource lcs = new ListCertificateSource(ccc);
		lcs.add(ccc);
		lcs.add(ctcs);

		assertEquals(2, lcs.getNumberOfCertificates());
		assertEquals(1, lcs.getNumberOfEntities());
		assertEquals(2, lcs.getBySubject(c1.getSubject()).size());
		assertEquals(2, lcs.getBySki(DSSASN1Utils.computeSkiFromCert(c1)).size());
		assertEquals(2, lcs.getBySki(DSSASN1Utils.computeSkiFromCert(c2)).size());
		assertEquals(2, lcs.getByPublicKey(c1.getPublicKey()).size());
		assertEquals(2, lcs.getByPublicKey(c2.getPublicKey()).size());

		assertTrue(lcs.isTrusted(c1));
		assertTrue(lcs.isTrusted(c2));
	}

	@Test
	public void extractTLSKeystore() {
		assertTimeout(ofMillis(30000), () -> {
			KeyStoreCertificateSource kscs = new KeyStoreCertificateSource(new File("src/test/resources/extract-tls.p12"),
					"PKCS12", "ks-password".toCharArray());
	
			CommonCertificateSource ccc = new CommonCertificateSource();
	
			for (CertificateToken cert : kscs.getCertificates()) {
				for (int i = 0; i < 10; i++) {
					ccc.addCertificate(cert);
				}
			}
	
			assertEquals(2438, ccc.getNumberOfCertificates());
			assertEquals(2338, ccc.getNumberOfEntities());
		});
	}

}
