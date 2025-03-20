/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DSS2199Test extends AbstractPAdESTestValidation {
	
	private CertificateVerifier certificateVerifier;
	
	@BeforeEach
	void init() {
		certificateVerifier = new CommonCertificateVerifier();
		certificateVerifier.setCrlSource(getCompositeCRLSource());
		
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIFOTCCBCGgAwIBAgIMVRYVFQAAAABRzhYOMA0GCSqGSIb3DQEBCwUAMIG0MRQwEgYDVQQKEwtFbnRydXN0Lm5ldDFAMD4GA1UECxQ3d3d3LmVudHJ1c3QubmV0L0NQU18yMDQ4IGluY29ycC4gYnkgcmVmLiAobGltaXRzIGxpYWIuKTElMCMGA1UECxMcKGMpIDE5OTkgRW50cnVzdC5uZXQgTGltaXRlZDEzMDEGA1UEAxMqRW50cnVzdC5uZXQgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgKDIwNDgpMB4XDTE2MDIyNTE4MDgxNloXDTI5MDYyNTE4MzgxNlowgbcxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAxNSBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxKzApBgNVBAMTIkVudHJ1c3QgQ2xhc3MgMyBDbGllbnQgQ0EgLSBTSEEyNTYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGnEvBT0qd2X3TO1eRq83pdhUtwCAvLDGGxQk9sB+RhJhDlS7UnqraVeLgYOi7B+/Lg+0uXxny0CjtOmQ/y64wYCHmZqtYTmJndk5SjNx7mEQODi2QULUh+42xza8hByWXz7oPGEcZTnHLabj6I20aBhE1wVa6n2Ih8bDxAY9ez/EiosFCDvXNMugrJ/SSbwsVXvz6aVKwjn6ky3W5RYS1kwMLcitAs25DQqETGRhkRNSmIAlFsDpkD1b95IUojrjUOCPHLuKw+5r7GjiBkzLnLR+ujjcXzvzCFD993yTsseygqo4jBIEce68pztTn1OFm6W5k6eEFsiqRmHBY2PILAgMBAAGjggFEMIIBQDAOBgNVHQ8BAf8EBAMCAQYwNAYDVR0lBC0wKwYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3CgMMBglghkgBhvprKAswOwYDVR0gBDQwMjAwBgRVHSAAMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuZW50cnVzdC5uZXQvcnBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwMwYIKwYBBQUHAQEEJzAlMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5lbnRydXN0Lm5ldDAyBgNVHR8EKzApMCegJaAjhiFodHRwOi8vY3JsLmVudHJ1c3QubmV0LzIwNDhjYS5jcmwwHQYDVR0OBBYEFAafb06iKU4PDK4Xv7aYRu+tuDtyMB8GA1UdIwQYMBaAFFXkgdERgL7YibkIozH5oSQJFrlwMA0GCSqGSIb3DQEBCwUAA4IBAQB8eBvEzfG7ciGMiBdPtSqio/2dh+DXHDyC2Z6Vkzd305spuLwA0olAKJKZgKFM804XffTDY4zCTvY3sX9gMvHUk1utlt2Kt8KPDfFLrfxL21sNyj79WG99p7vrzVlsO+8AFZU2AdTLPLVjz9/Tmqr5RRKyq4IPZg0uaAM4+m6VIOceWnYEI2A9S+XpEHWqF9vbCevuF0iLnZalaqPdTBkfYkAuD/T6AOZabkbolo2bjssLzYsHOZExFCFu37kJZTw/JaDlC7o6A0r0QaZojaXqYM0jSfppwIWH58keRNVFyBIApO0GmIpBSieh8hZlo1X6K0yukH+M53cikOr4IS/F"));
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
		certificateVerifier.setTrustedCertSources(trustedCertificateSource);
	}

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2199.pdf"));
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		validator.setCertificateVerifier(certificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		// LT level as validation data for the timestamp has been added after the timestamp and there is no TST covering it
		assertEquals(SignatureLevel.PKCS7_LT, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);

		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(1, signature.getDocumentTimestamps().size());
		assertEquals(1, signature.getTLevelTimestamps().size());
		assertEquals(0, signature.getALevelTimestamps().size());
	}

	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(1, diagnosticData.getAllOrphanRevocationObjects().size()); // CRL from an orphan DSS dictionary
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}

}
