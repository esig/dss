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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESWithMultipleCertRefsTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/jades-with-multiple-sign-cert-refs.json");
	}

	@Override
	protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
		SignedDocumentValidator validator = super.getValidator(signedDocument);
		CertificateVerifier completeCertificateVerifier = getOfflineCertificateVerifier();
		CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
		trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkxMDE0MDUzODQ0WhcNMjExMDE0MDUzODQ0WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDULeex4u8ebUQEfm0V0em+r1AqpR11+84XlxFJyEMDOhCbPOOQI68HVIVWt/GX7naFUoiAPm0IhlAYlq0/amBxg/Q8wW9a6KZc4o3DFgGIBFNEOYHCSwJPQ8EtcSmWZ/+Fgb7+lPffbTCucaOgax5VRFQp6c0fswCmcA9jukxeFCDOz8HNQqBiKvuRmkAj8NmwgQHx/Sndo7YdkalPr2qJ+gBRdg6JANIWuYahxixypqP5He+3pb0ghjWOjCnaIg2K2PQUy6i8YTnagwyGS/FxhXpdLatdUhjUdgkvLn1ZyxqvCbOZsiUx55p2FljR3fSUgt9+VOwC4WzZVLtZHZejAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUXB8V7Y9AxDcPJ5i36BC54z8jWyowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAOem7HjwO2cGZlFYSAGby13r8gTkY9Dtq1GbsB+kawdUt6d86tmAw3zNKaPb4qAuZtEeM5tVfW2bj1eN+FzI+T9ZDDEnU50Y9x+DC6q3ZBPk46x0XK+7frnyDkhikRyZ5yss6dqoo8nKgIQUEXdeOky6cK2ybUcGUwzgVn/GalLEcA6zILHp7NAsOxzbwsCEgeWY9CBW5/3GAp/2qo1NNPXukazd9/a5KOeRht2iRjXISUWWJKFHsAJtsmZrul+hfTGorjc6rG+PMNnWK7X5rB/6ZwSVG6naxuoaunIrp99rDuSw9k8pvcyXzofaXDlFYPe1vVyc14Bhtca8A4YI6Jw=="));
		completeCertificateVerifier.addTrustedCertSources(trustedCertificateSource);
		validator.setCertificateVerifier(completeCertificateVerifier);
		return validator;
	}

	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signatureWrapper);

		assertTrue(signatureWrapper.isSigningCertificateIdentified());
		assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
		assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());

		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		List<RelatedCertificateWrapper> signCertificateRefs = foundCertificates
				.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		assertNotNull(signCertificateRefs);
		assertEquals(3, signCertificateRefs.size());
	}

}
