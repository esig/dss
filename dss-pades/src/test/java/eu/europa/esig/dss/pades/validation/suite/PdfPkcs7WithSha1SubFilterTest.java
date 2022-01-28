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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureForm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PAdESConstants;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdfPkcs7WithSha1SubFilterTest extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/pkcs7_sha1.pdf"));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(SignatureForm.PKCS7, signatureWrapper.getSignatureFormat().getSignatureForm());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        boolean sigWithSignCertFound = false;
        boolean sigWithoutSignCertFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isSigningCertificateReferencePresent()) {
                sigWithSignCertFound = true;
            } else {
                sigWithoutSignCertFound = true;
            }
        }
        assertTrue(sigWithSignCertFound);
        assertTrue(sigWithoutSignCertFound);
    }

    @Override
    protected void checkPdfRevision(DiagnosticData diagnosticData) {
        super.checkPdfRevision(diagnosticData);

        boolean sha1Pkcs7SigFound = false;
        boolean detachedPkcs7SigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            String subFilter = signatureWrapper.getSubFilter();
            if (PAdESConstants.SIGNATURE_PKCS7_SHA1_SUBFILTER.equals(subFilter)) {
                sha1Pkcs7SigFound = true;
            } else if (PAdESConstants.SIGNATURE_PKCS7_SUBFILTER.equals(subFilter)) {
                detachedPkcs7SigFound = true;
            }
        }
        assertTrue(sha1Pkcs7SigFound);
        assertTrue(detachedPkcs7SigFound);
    }

    @Override
    protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
        super.checkMessageDigestAlgorithm(diagnosticData);

        boolean sha1Pkcs7SigFound = false;
        boolean detachedPkcs7SigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            assertEquals(1, digestMatchers.size());

            XmlDigestMatcher xmlDigestMatcher = digestMatchers.get(0);
            if (DigestMatcherType.CONTENT_DIGEST.equals(xmlDigestMatcher.getType())) {
                assertEquals(DigestAlgorithm.SHA1, xmlDigestMatcher.getDigestMethod());
                sha1Pkcs7SigFound = true;
            } else if (DigestMatcherType.MESSAGE_DIGEST.equals(xmlDigestMatcher.getType())) {
                detachedPkcs7SigFound = true;
            }
        }
        assertTrue(sha1Pkcs7SigFound);
        assertTrue(detachedPkcs7SigFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        boolean emptySigDocFound = false;
        boolean signPdfFound = false;
        for (AdvancedSignature signature : signatures) {
            List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signature.getId());
            if (originalDocuments.size() == 0) {
                emptySigDocFound = true;
            } else {
                signPdfFound = true;
            }
        }
        assertTrue(emptySigDocFound);
        assertTrue(signPdfFound);
    }

}
