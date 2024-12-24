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

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PdfPkcs7SubFilterValidAndInvalidTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pkcs7-no-message-digest.pdf"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(PAdESConstants.SIGNATURE_PKCS7_SUBFILTER, signatureWrapper.getSubFilter());

        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        assertEquals(1, digestMatchers.size());
        assertEquals(DigestMatcherType.CONTENT_DIGEST, digestMatchers.get(0).getType());
        assertEquals(SignatureLevel.PDF_NOT_ETSI, signatureWrapper.getSignatureFormat());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertFalse(signatureWrapper.isSigningCertificateIdentified());
            assertFalse(signatureWrapper.isSigningCertificateReferencePresent());

            CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
            assertNotNull(signingCertificate);
        }
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip (only one revision)
    }

}
