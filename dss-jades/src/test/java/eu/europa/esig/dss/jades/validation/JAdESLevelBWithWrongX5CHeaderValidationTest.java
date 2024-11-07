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

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignerInformationType;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JAdESLevelBWithWrongX5CHeaderValidationTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-wrong-x5c-header.json");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertNotNull(signature);
        assertFalse(signature.isBLevelTechnicallyValid());

        List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
        assertEquals(1, digestMatchers.size());

        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.JWS_SIGNING_INPUT_DIGEST, digestMatcher.getType());
        assertTrue(digestMatcher.isDataFound());
        assertFalse(digestMatcher.isDataIntact());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertTrue(signature.isSigningCertificateReferencePresent());

        CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
        assertNotNull(signingCertificateReference);
        assertTrue(signingCertificateReference.isDigestValuePresent());
        assertFalse(signingCertificateReference.isDigestValueMatch());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());

        List<String> structuralValidationMessages = signature.getStructuralValidationMessages();
        assertEquals(1, structuralValidationMessages.size());
        assertTrue(structuralValidationMessages.get(0).contains("x5c"));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(Utils.isCollectionEmpty(signature.getSignatureScopes()));
    }

    @Override
    protected void validateSignerInformation(SignerInformationType signerInformation) {
        assertNull(signerInformation);
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        assertNull(signersDocument);
    }

    @Override
    protected void checkReportsTokens(Reports reports) {
        // skip
    }

}
