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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class CAdESCounterSignedWithLTALevelTest extends AbstractCAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/counterSignedLTA.p7s");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwODAzMDYzMjQ3WhcNMjEwODAzMDYzMjQ3WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ7JX2q8QypdrznoMbaEUw6ihqNcX/Nl+sBOdydkKNH3Nt869KujIO9xpRBKpKICwQvw1lHdF0/I/OUXXki845fPp8WhgZzU5rEpySGLBMCAMe908vIVgoIHWlsXGs5FhHjpFrdHaW5+YdtcrlUb8llQVEAnX50LN1LB7T6mjg1UzEDd3TuHa1CcIn9OI0cLEeTL3ebH0MgDJr3IGJAwDicjYMIpLMBNax947WLEvMs8uzzr/+1m5ycwgnq+CceeGqvjWSfK+w7hu7wdqKtXwpQcmE2qRe7dj4r7szuHFagqyD2TtHAVKeUo6g0glxweVnyTtngk/SzpLDx3WnDkvlAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU9S5pd1uILQPiX0wzF2r7VAOtRf4wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAUGayYIni5o7a/O9YZl92ZNOFQ2aHKWZ0BVVGnOsrSuNVX1l7p32CwvvfJNcdtKcbgp7Nh++u+zTWyR7fT+VwEt2fFTZ8ed1Gq6c/IiPCqR4YQ3eaydqWpEcP1WhJ6rHUAxxlqQcFPm5cqMcIxz6aD1PFOTiLVPd6+9+Ei39Lorx0ww0xw1IQ74LGIvUC/0kmjMTooEiO/bpaFWXiwR8fejxlklR/6fhh2SIi04hciPty/Bs47ameno29DhBDvMxWvIpRF2TBNhezWyivbjPYFVFJbQkVwW44mLkRyI7PyCyw9ejN9R8+ve/l3HFCpd14gWWIsXUr1PXaC7iXd5uCpQ=="));
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIE7jCCA9agAwIBAgILBAAAAAABQaHhPSYwDQYJKoZIhvcNAQELBQAwOzEYMBYGA1UEChMPQ3liZXJ0cnVzdCwgSW5jMR8wHQYDVQQDExZDeWJlcnRydXN0IEdsb2JhbCBSb290MB4XDTEzMTAxMDExMDAwMFoXDTI1MDUxMjIyNTkwMFowKDELMAkGA1UEBhMCQkUxGTAXBgNVBAMTEEJlbGdpdW0gUm9vdCBDQTQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCYkK76xx5vjuAFOrMjeEzR1i/ddTxbGOhPXrsFZpeTQFk3cPadpnJhDmBseNuIxS6UkFTcccaIdy7CKXVlDEUH7og6s72cf+HQgWnii/wDESbi9XesFO91ykpHQ6+bh+h9mH9fc0olDptseJN2jS8k/la8hddW9T66euwgZOtzgZhtFlGgfhMbQRzpHz2h0RxQNODIoKFRbd4C0ERodVfh9a5tYcnU83es86aCR6d7o1g+K+JCwq8VRVdEGeOLrLwD5YSqHnBdH3oirXoEtaUvhYxhwPUvOcsWZJxFfDem2yuWD+5IDSwwwjRSehuzDKX/DBMoF1jG/lq8p03rVpyFeo082QNUZmmbqpiDA71kwOyTZIgyUDiQVkNxIaflZ+5YtTAiI15RA2CdsEZnEWUNG7FM2jP1d6fkPo/Et6LJmtz3OvnQ88S/joP5Z0Zy5Q2qV8dvFwfbq1EeR9Nzs5u+wff5mICHjPGNV57ZQghCwXriXhGCVKnNBbBsVjcI7AbUaGeHb2ta785F5oybjSEeGCC4PBuJCi4a/SQ67cgpLyPV5vBg46kCCdiqUIiRwSyQNICsZWHpvAkjv2p9wDsakzWY1m0MehN9jjwf67FNvJXWnYvXPMnkcly1qVBeBoY8qHODnawJF5pY55MyzAuOfcRi/II+i8jW+lM19HmAPQIDAQABo4IBBDCCAQAwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwUAYDVR0gBEkwRzBFBgorBgEEAbE+AWQBMDcwNQYIKwYBBQUHAgEWKWh0dHA6Ly9jeWJlcnRydXN0Lm9tbmlyb290LmNvbS9yZXBvc2l0b3J5MB0GA1UdDgQWBBRn6PFOT7O18wdvCJwMg9l62VvnSTA1BgNVHR8ELjAsMCqgKKAmhiRodHRwOi8vY3JsLm9tbmlyb290LmNvbS9jdGdsb2JhbC5jcmwwEQYJYIZIAYb4QgEBBAQDAgAHMB8GA1UdIwQYMBaAFLYIew16zKwgTIZWMl7Pq26FLXBXMA0GCSqGSIb3DQEBCwUAA4IBAQBcwXlO+W1txa4MNqD0Tq5ofwESbZ0Rrxoh0RYNqXafZR7Yjj6sEKSSz/WgN8CQYzEWPB6BaScM+VYgOFq9lqr5aedzcsjStqq5uAUXlgnpWXLVBsvKLKR9cKLXE6i7T+juFaKYSO0fNGtPm6KJ/7qvNO3KhocJiDjhykUxV92UDgNXMMH2FhBM/7+k14UgIEllq8zds225jqz9fuS8Srv2lutEv2BLsG6V4GmU9yz2nuLt8X3McwPhh6X5Ae0Pd1gvofOQF+qDtuR4d3NuUt/dHXLPzQfd0t4gMRIM/09GE+dNzRB8p1YRaT4zHRlhH+CHDGjHMIBbb69s9wcD+s/t"));
		CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
		certificateVerifier.setTrustedCertSources(trustedCertificateSource);
		validator.setCertificateVerifier(certificateVerifier);
		
		return validator;
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertFalse(signature.isCounterSignature());
		
		Set<SignatureWrapper> counterSignatures = diagnosticData.getAllCounterSignatures();
		assertEquals(1, counterSignatures.size());
		SignatureWrapper counterSignature = counterSignatures.iterator().next();
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		boolean sigTstFound = false;
		boolean arcTstFound = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
				sigTstFound = true;
				
			} else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
				assertEquals(2, timestampWrapper.getTimestampedSignatures().size());
				assertTrue(timestampWrapper.getTimestampedSignatures().stream().map(s -> s.getId()).collect(Collectors.toList())
						.contains(counterSignature.getId()));
				assertTrue(timestampWrapper.getTimestampedCertificates().stream().map(c -> c.getId()).collect(Collectors.toList())
						.contains(counterSignature.getSigningCertificate().getId()));
				arcTstFound = true;
				
			}
		}
		assertTrue(sigTstFound);
		assertTrue(arcTstFound);
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		for (String signatureId : diagnosticData.getSignatureIdList()) {
			if (diagnosticData.getSignatureById(signatureId).isCounterSignature()) {
				assertEquals(SignatureLevel.CAdES_BASELINE_B, diagnosticData.getSignatureFormat(signatureId));
			} else {
				assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(signatureId));
			}
		}
	}

}
