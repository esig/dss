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
package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocRefImplValidationTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
    }

    @Override
    protected DSSDocument getSessionTranscript() {
        return null;
    }

    @Override
    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return true;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        boolean eaaSignatureFound = false;
        boolean kbSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertFalse(signatureWrapper.isBLevelTechnicallyValid());
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                kbSignatureFound = true;
            } else {
                assertTrue(signatureWrapper.isBLevelTechnicallyValid());
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                eaaSignatureFound = true;
            }
        }
        assertTrue(eaaSignatureFound);
        assertTrue(kbSignatureFound);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signatureWrapper.isSigningCertificateIdentified());
        assertFalse(signatureWrapper.isSigningCertificateReferencePresent());
        assertFalse(signatureWrapper.isSigningCertificateReferenceUnique());

        CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
        assertNull(signingCertificateReference);

        CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
        assertNotNull(signingCertificate);
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNull(signatureWrapper.getClaimedSigningTime());
    }

    @Override
    protected void checkDTBSR(DiagnosticData diagnosticData) {
        boolean eaaSignatureFound = false;
        boolean kbSignatureFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isKeyBindingSignature()) {
                assertNull(signatureWrapper.getDataToBeSignedRepresentation());
                kbSignatureFound = true;
            } else {
                assertNotNull(signatureWrapper.getDataToBeSignedRepresentation());
                eaaSignatureFound = true;
            }
        }
        assertTrue(eaaSignatureFound);
        assertTrue(kbSignatureFound);
    }

    @Override
    protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
        // skip
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        // skip
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
