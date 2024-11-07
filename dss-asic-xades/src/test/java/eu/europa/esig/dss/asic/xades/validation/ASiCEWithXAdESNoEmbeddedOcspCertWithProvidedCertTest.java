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
package eu.europa.esig.dss.asic.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

class ASiCEWithXAdESNoEmbeddedOcspCertWithProvidedCertTest extends AbstractASiCWithXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-A-EE_AS-6.asice");
	}
	
	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CommonTrustedCertificateSource commonTrustedCertificateSource = new CommonTrustedCertificateSource();
		commonTrustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEvDCCA6SgAwIBAgIQcpyVmdruRVxNgzI3N/NZQTANBgkqhkiG9w0BAQUFADB1MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czEoMCYGA1UEAwwfRUUgQ2VydGlmaWNhdGlvbiBDZW50cmUgUm9vdCBDQTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMB4XDTExMDMxODEwMjE0M1oXDTI0MDMxODEwMjE0M1owgZ0xCzAJBgNVBAYTAkVFMQ4wDAYDVQQIEwVIYXJqdTEQMA4GA1UEBxMHVGFsbGlubjEiMCAGA1UEChMZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1czENMAsGA1UECxMET0NTUDEfMB0GA1UEAxMWU0sgT0NTUCBSRVNQT05ERVIgMjAxMTEYMBYGCSqGSIb3DQEJARYJcGtpQHNrLmVlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAihvGyhMVrgReHluKln1za6gvCE/mlSREmWjJFpL9llvuEUZoPFIypYA8g5u1VfgkeW5gDq25jAOq4FyXeDGIa+pJn2h0o2Wc2aeppVG/emfGm/jA8jjeyMrwH8fAJrqVQ7c9X2xSwJEch/P2d8CfMZt5YF6gqLtPvG1b+n6otBZA5wjIFfJ/inJBMUvqHSz3+PLfxO2/T3Wyk/c8M9HIMqTelqyiMGRgWehiU1OsL9armv3dQrHs1wm6vHaxfpfWB9YAFpeo9aYqhPCxVt/zo2NQB6vxyZS0hsOrXL7SxRToOJaqsnvlbf0erPPFtRHUvbojYYgl+fzlz0Jt6QJoNwIDAQABo4IBHTCCARkwEwYDVR0lBAwwCgYIKwYBBQUHAwkwHQYDVR0OBBYEFKWhSGFt537NmJ50nCm7vYrecgxZMIGCBgNVHSAEezB5MHcGCisGAQQBzh8EAQIwaTA+BggrBgEFBQcCAjAyHjAAUwBLACAAdABpAG0AZQAgAHMAdABhAG0AcABpAG4AZwAgAHAAbwBsAGkAYwB5AC4wJwYIKwYBBQUHAgEWG2h0dHBzOi8vd3d3LnNrLmVlL2FqYXRlbXBlbDAfBgNVHSMEGDAWgBQS8lo+6lYcv80GrPHxJcmpS9QUmTA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vd3d3LnNrLmVlL3JlcG9zaXRvcnkvY3Jscy9lZWNjcmNhLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAw2sKwvTHtYGtD8Jw9mNUuj/mWiBSBEBeY2LhW8V6tjBPAPp3s6iWOh0FbVR2LUyrqRwgT3fyWiGsiDm/6cIqM+IblLp/8ztfRQjquhW6XCD9SK02OQ9ZSdBwcmoAApZLGXQC34wdgmV/hLTTNxONnDACBKz9U+Dy9a4ZT4tpNkbH8jq/BMne8FzbvRt1bjpXBP7gjLX+zdx8/hp0Wq4tD+f9NVX0+vm9ahEKuzx4QzPnSB7hhWM9OnLZT7noRQa+KWk5c+e5VoR5R2t7MjVl8Cd+2llxiSxqMSbU5/23BzAKgN+NQdrBZAzpZ7lfaAuLFaICP+bAm6uW2JUrM6abOw=="));
		CertificateVerifier offlineCertificateVerifier = getOfflineCertificateVerifier();
		offlineCertificateVerifier.setTrustedCertSources(commonTrustedCertificateSource);
		validator.setCertificateVerifier(offlineCertificateVerifier);
		return validator;
	}
	
	@Override
	protected void checkRevocationData(DiagnosticData diagnosticData) {
		super.checkRevocationData(diagnosticData);
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(1, allRevocationData.size());
		
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertNotNull(revocationWrapper.getSigningCertificate());
		assertTrue(revocationWrapper.isSignatureValid());
		
		FoundCertificatesProxy foundCertificates = revocationWrapper.foundCertificates();
		assertTrue(Utils.isCollectionNotEmpty(foundCertificates.getRelatedCertificates()));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		RevocationWrapper revocationWrapper = allRevocationData.iterator().next();
		assertEquals(1, revocationWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
	}

}
