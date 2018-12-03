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
package eu.europa.esig.dss.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.CommonTrustedCertificateSource;

public class BaselineBCertificateSelectorTest {

	// Signer
	private CertificateToken c1;

	// CA
	private CertificateToken c2;

	// Root self signed
	private CertificateToken c3;

	// Root not self signed
	private CertificateToken c3Bis;

	// Other root (different chain)
	private CertificateToken c4;

	@Before
	public void init() {
		c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		c2 = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");

		// c3 and c3Bis represent the same entity
		c3 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIFjjCCA3agAwIBAgIITzMgjMWUvzgwDQYJKoZIhvcNAQELBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTQwHhcNMTMwNjI2MTIwMDAwWhcNMzIxMDIyMTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJiQrvrHHm+O4AU6syN4TNHWL911PFsY6E9euwVml5NAWTdw9p2mcmEOYGx424jFLpSQVNxxxoh3LsIpdWUMRQfuiDqzvZx/4dCBaeKL/AMRJuL1d6wU73XKSkdDr5uH6H2Yf19zSiUOm2x4k3aNLyT+VryF11b1Prp67CBk63OBmG0WUaB+ExtBHOkfPaHRHFA04MigoVFt3gLQRGh1V+H1rm1hydTzd6zzpoJHp3ujWD4r4kLCrxVFV0QZ44usvAPlhKoecF0feiKtegS1pS+FjGHA9S85yxZknEV8N6bbK5YP7kgNLDDCNFJ6G7MMpf8MEygXWMb+WrynTetWnIV6jTzZA1RmaZuqmIMDvWTA7JNkiDJQOJBWQ3Ehp+Vn7li1MCIjXlEDYJ2wRmcRZQ0bsUzaM/V3p+Q+j8S3osma3Pc6+dDzxL+Og/lnRnLlDapXx28XB9urUR5H03Ozm77B9/mYgIeM8Y1XntlCCELBeuJeEYJUqc0FsGxWNwjsBtRoZ4dva1rvzkXmjJuNIR4YILg8G4kKLhr9JDrtyCkvI9Xm8GDjqQIJ2KpQiJHBLJA0gKxlYem8CSO/an3AOxqTNZjWbQx6E32OPB/rsU28ldadi9c8yeRyXLWpUF4Ghjyoc4OdrAkXmljnkzLMC459xGL8gj6LyNb6UzX0eYA9AgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAwBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUZ+jxTk+ztfMHbwicDIPZetlb50kwEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFGfo8U5Ps7XzB28InAyD2XrZW+dJMA0GCSqGSIb3DQEBCwUAA4ICAQBe3CQAZrNwVZ9Ll3nFWkaKDvMwOE2s1NysTfocGUwyd6c01qsSN52BhRqpaSEWLeSXAfPQK+f57M1hXLNVE8VMf1Vtc0ge+VgjKOWLJ+4d0CAk8VIAK55NUkrSbu4pn+osfD/He0jfECKyq9xrhbn4yxZ/d5qj8RSj+aPmCoX/kaODZmug+AfzY+TXeJgjn8eEQGO8zDJoV/hdUuotkf8eQXeuRhoCuvipBm7vHqEA946NuVtRUmaztLUR9CkbSZ1plWWmqKC+QKErWzvBeswrWxzaRoW9Un7qCSmiO9ddkEHVRHibkUQvPn8kGdG/uOmmRQsbjFuARNCMWS4nHc6TTw7dJgkeZjZiqPl22ifsWJsR/w/VuJMA4kSot/h6qQV9Eglo4ClRlEk3yzbKkcJkLKk6lA90/u46KsqSC5MgUeFjER398iXqpDpT8BzIMovMzHlK7pxTJA5cWXN2a8OMhYCA/Kb6dqIXIi8NKsqzVMXJfX65DM2gWA8rjicJWoooqLhUKuZ6tSWA6If2TRr7MfQsVDhwwUk6mvEIaBJBcyOWH8XgyY6uuHuvGe8CkK+Yk4X2TiE+7GuQe4YVJ/MOGdS3V1eZwPmWSu++azOOFrwoZpIPKOwjbsuLbs0xt6BwWW2XFP025BDh/OD6UE4VsyznnUCkb4AbS947UX6NGA==");

		c3Bis = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIE7jCCA9agAwIBAgILBAAAAAABQaHhPSYwDQYJKoZIhvcNAQELBQAwOzEYMBYGA1UEChMPQ3liZXJ0cnVzdCwgSW5jMR8wHQYDVQQDExZDeWJlcnRydXN0IEdsb2JhbCBSb290MB4XDTEzMTAxMDExMDAwMFoXDTI1MDUxMjIyNTkwMFowKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCYkK76xx5vjuAFOrMjeEzR1i/ddTxbGOhPXrsFZpeTQFk3cPadpnJhDmBseNuIxS6UkFTcccaIdy7CKXVlDEUH7og6s72cf+HQgWnii/wDESbi9XesFO91ykpHQ6+bh+h9mH9fc0olDptseJN2jS8k/la8hddW9T66euwgZOtzgZhtFlGgfhMbQRzpHz2h0RxQNODIoKFRbd4C0ERodVfh9a5tYcnU83es86aCR6d7o1g+K+JCwq8VRVdEGeOLrLwD5YSqHnBdH3oirXoEtaUvhYxhwPUvOcsWZJxFfDem2yuWD+5IDSwwwjRSehuzDKX/DBMoF1jG/lq8p03rVpyFeo082QNUZmmbqpiDA71kwOyTZIgyUDiQVkNxIaflZ+5YtTAiI15RA2CdsEZnEWUNG7FM2jP1d6fkPo/Et6LJmtz3OvnQ88S/joP5Z0Zy5Q2qV8dvFwfbq1EeR9Nzs5u+wff5mICHjPGNV57ZQghCwXriXhGCVKnNBbBsVjcI7AbUaGeHb2ta785F5oybjSEeGCC4PBuJCi4a/SQ67cgpLyPV5vBg46kCCdiqUIiRwSyQNICsZWHpvAkjv2p9wDsakzWY1m0MehN9jjwf67FNvJXWnYvXPMnkcly1qVBeBoY8qHODnawJF5pY55MyzAuOfcRi/II+i8jW+lM19HmAPQIDAQABo4IBBDCCAQAwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwUAYDVR0gBEkwRzBFBgorBgEEAbE+AWQBMDcwNQYIKwYBBQUHAgEWKWh0dHA6Ly9jeWJlcnRydXN0Lm9tbmlyb290LmNvbS9yZXBvc2l0b3J5MB0GA1UdDgQWBBRn6PFOT7O18wdvCJwMg9l62VvnSTA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLm9tbmlyb290LmNvbS9jdGdsb2JhbC5jcmwwEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFLYIew16zKwgTIZWMl7Pq26FLXBXMA0GCSqGSIb3DQEBCwUAA4IBAQBcwXlO+W1txa4MNqD0Tq5ofwESbZ0Rrxoh0RYNqXafZR7Yjj6sEKSSz/WgN8CQYzEWPB6BaScM+VYgOFq9lqr5aedzcsjStqq5uAUXlgnpWXLVBsvKLKR9cKLXE6i7T+juFaKYSO0fNGtPm6KJ/7qvNO3KhocJiDjhykUxV92UDgNXMMH2FhBM/7+k14UgIEllq8zds225jqz9fuS8Srv2lutEv2BLsG6V4GmU9yz2nuLt8X3McwPhh6X5Ae0Pd1gvofOQF+qDtuR4d3NuUt/dHXLPzQfd0t4gMRIM/09GE+dNzRB8p1YRaT4zHRlhH+CHDGjHMIBbb69s9wcD+s/t");

		c4 = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIFjjCCA3agAwIBAgIIOyEC3pZbHakwDQYJKoZIhvcNAQEFBQAwKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTMwHhcNMTMwNjI2MTIwMDAwWhcNMjgwMTI4MTIwMDAwWjAoMQswCQYDVQQGEwJCRTEZMBcGA1UEAxMQQmVsZ2l1bSBSb290IENBMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKjyAZ2Lg8kHoIX7JLc3BeZ1Tzy9MEv7Bnr59xcJezc/xJJdO4V3bwMltKFfNvqsQ5H/GQADFJ0GmTLLPDI5AoeUjBubRZ9hwruUuQ11+vhtoVhuEuZUxofEIU2yJtiSOONwpo/GIb9C4YZ5h+7ltDpC3MvsFyyordpzgwqSHvFwTCmls5SpU05UbF7ZVPcfVf24A5IgHLpZTgQfAvnzPlm++eJY+sNoNzTBoe6iZphmPbxuPNcJ6slV8qMQQk50/g+KmoPpHX4AvoTr4/7TMTvuK8jS1dEn+fdVKdx9qo9ZZRHFW/TXEn5SrNUu99xhzlE/WBurrVwFoKCWCjmO0CnekJlw0NTr3HBTG5D4AiDjNFUYaIcGJk/ha9rzHzY+WpGdoFZxhbP83ZGeoqkgBr8UzfOFCY8cyUN2db6hpIaK6Nuoho6QWnn+TSNh5Hjui5miqpGxS73gYlT2Qww16h8gFTJQ49fiS+QHlwRw5cqFuqfFLE3nFFF9KIamS4TSe7T4dNGY2VbHzpaGVT4wy+fl7gWsfaUkvhM4b00DzgDiJ9BHiKytNLmzoa3Sneij/CKur0dJ5OdMiAqUpSd0Oe8pdIbmQm1oP5cjckiQjxx7+vSxWtacpGowWK8+7oEsYc+7fLt3GD6q/O5Xi440Pd/sFJmfqRf3C1PPMdBqXcwjAgMBAAGjgbswgbgwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wQgYDVR0gBDswOTA3BgVgOAoBATAuMCwGCCsGAQUFBwIBFiBodHRwOi8vcmVwb3NpdG9yeS5laWQuYmVsZ2l1bS5iZTAdBgNVHQ4EFgQUuLxsAI9bGYWdJQGc8BncQI7QOCswEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFLi8bACPWxmFnSUBnPAZ3ECO0DgrMA0GCSqGSIb3DQEBBQUAA4ICAQBFYjv/mKX+VcyxEacckgx4L8XvFkIFPXzjEnDnAtCCkROU/k5n1jjVK+ODOn+Q4kJg6Nd7K47+zTXcrSe1tB2gVMsyaCN9scy4phLX1qT48sThCjUtooxfIoRycpdlf14HcUPCYlASTCapZU0MnAbzfpzxm49Ik/A2JWxAhxXVRHwOu3TMGiQ4W/VyVawxjwQMO8TneBDombmkXsI9bI0OxWUh2A5dKlqu0sYvE0dz8xDxr9ZkmZqYcPIKizCZlaP1ZsSlCi5S31gn3EUP+fd21q6ZXgU+50/qgoh/0UUaHRpedPQBES/FYc2IQZ2XjhmeTwM+9Lk7tnzHeHp3dgCoOfceyPUaVkWiXMWcNAvvkDVELvXfJpRxwcRfS5Ks5oafOfj81RzGUbmpwl2usOeCRwdWE8gPvbfWNQQC8MJquDl5HdeuzUesTXUqXeEkyAOo6YnF3g0qGcLI9NXusji1egRUZ7B4XCvG52lTB7Wgd/wVFzS3f4mAmYTGJXH+N/lrBBGKuTJ5XncJaliFUKxGP6VmNyaaLUF5IlTqC9CGHPLSXOgDokt2G9pNwFm2t7AcpwAmegkMNpgcgTd+qk2yljEaT8wf953jUAFedbpN3tX/3i+uvHOOmWjQOxJg2lVKkC+bkWa2FrTBDdrlEWVaLrY+M+xeIctrC0WnP7u4xg==");
	}

	@Test
	public void testNormalNoTrust() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@Test
	public void testNormalTrust() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c2);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(1, certificates.size());
		assertEquals(c1, certificates.get(0));
	}

	@Test
	public void testSkipTrustAndUpper() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c2);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2, c3);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(1, certificates.size());
		assertEquals(c1, certificates.get(0));

		for (CertificateToken certificateToken : certificates) {
			assertTrue(certificateToken.isSignatureValid());
		}
	}

	@Test
	public void testNormalTrust2() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c3);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2, c3);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@Test
	public void testNormalTrustOtherRoot() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c3Bis);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2, c3);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@Test
	public void testNormalTrustTooMuch() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c3);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2, c3, c4);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@Test
	public void testNormalIncludeTrust() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c2);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c2);
		parameters.bLevel().setTrustAnchorBPPolicy(false);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@Test
	public void testNormalIncludeTrustFixChainOrder() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CertificateSource trustCertSource = new CommonTrustedCertificateSource();
		trustCertSource.addCertificate(c3);
		certificateVerifier.setTrustedCertSource(trustCertSource);

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c3, c2);
		parameters.bLevel().setTrustAnchorBPPolicy(false);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(3, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
		assertEquals(c3, certificates.get(2));
	}

	@Test
	public void testDuplicateSigningCert() {
		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();

		AbstractSignatureParameters parameters = new CommonSignatureParamaters();
		parameters.setSigningCertificate(c1);
		parameters.setCertificateChain(c1, c2);

		BaselineBCertificateSelector selector = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificates = selector.getCertificates();
		assertEquals(2, certificates.size());
		assertEquals(c1, certificates.get(0));
		assertEquals(c2, certificates.get(1));
	}

	@SuppressWarnings("serial")
	private static class CommonSignatureParamaters extends AbstractSignatureParameters {
	}

}
