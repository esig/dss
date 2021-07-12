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
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithBrokenAttachedCounterSignatureTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-with-broken-attached-counter-signature.json");
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        int masterSignatureCounter = 0;
        int counterSignatureCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
            if (signatureWrapper.isCounterSignature()) {
                assertEquals(2, digestMatchers.size());
                boolean jwsSignatureInputFound = false;
                boolean counterSignedSignatureInputFound = false;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.JWS_SIGNING_INPUT_DIGEST.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        jwsSignatureInputFound = true;
                    } else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        counterSignedSignatureInputFound = true;
                    }
                }
                assertTrue(jwsSignatureInputFound);
                assertTrue(counterSignedSignatureInputFound);
                ++counterSignatureCounter;
            } else {
                assertEquals(1, digestMatchers.size());
                XmlDigestMatcher digestMatcher = digestMatchers.get(0);
                assertEquals(DigestMatcherType.JWS_SIGNING_INPUT_DIGEST, digestMatcher.getType());
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                ++masterSignatureCounter;
            }
        }
        assertEquals(1, masterSignatureCounter);
        assertEquals(1, counterSignatureCounter);

    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        int signatureScopesForMasterSignatureCounter = 0;
        int signatureScopesForCounterSignatureCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                signatureScopesForCounterSignatureCounter += signatureWrapper.getSignatureScopes().size();
            } else {
                signatureScopesForMasterSignatureCounter += signatureWrapper.getSignatureScopes().size();
            }
        }
        assertEquals(1, signatureScopesForMasterSignatureCounter);
        assertEquals(0, signatureScopesForCounterSignatureCounter);
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
