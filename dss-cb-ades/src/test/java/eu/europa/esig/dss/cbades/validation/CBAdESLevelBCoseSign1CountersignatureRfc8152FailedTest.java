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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBCoseSign1CountersignatureRfc8152FailedTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-cosesign1-countersignature-rfc8152-fail.cose");
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());

        boolean masterSigFound = false;
        boolean counterSigFound = false;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (!signatureWrapper.isCounterSignature()) {
                assertEquals(COSESignatureType.COSE_SIGN1, signatureWrapper.getCOSESignatureType());
                masterSigFound = true;
            } else {
                assertEquals(COSESignatureType.COSE_COUNTER_SIGNATURE, signatureWrapper.getCOSESignatureType());
                counterSigFound = true;
            }
        }
        assertTrue(masterSigFound);
        assertTrue(counterSigFound);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());

        boolean masterSigFound = false;
        boolean counterSigFound = false;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (!signatureWrapper.isCounterSignature()) {
                assertTrue(signatureWrapper.isSignatureIntact());
                assertTrue(signatureWrapper.isSignatureValid());
                assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
                masterSigFound = true;
            } else {
                assertFalse(signatureWrapper.isSignatureIntact());
                assertFalse(signatureWrapper.isSignatureValid());
                assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));

                List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
                assertEquals(2, digestMatchers.size());

                boolean coseInputDMFound = false;
                boolean counterSigDMFound = false;
                for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
                    if (DigestMatcherType.COSE_SIG_STRUCTURE == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        coseInputDMFound = true;
                    } else if (DigestMatcherType.COUNTER_SIGNED_SIGNATURE_VALUE == xmlDigestMatcher.getType()) {
                        // counter-signature is not covered by RFC 8152 counter-signature
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        counterSigDMFound = true;
                    }
                }
                assertTrue(coseInputDMFound);
                assertTrue(counterSigDMFound);

                counterSigFound = true;
            }
        }
        assertTrue(masterSigFound);
        assertTrue(counterSigFound);
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(2, signatures.size());

        boolean masterSigFound = false;
        boolean counterSigFound = false;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (!signatureWrapper.isCounterSignature()) {
                assertFalse(signatureWrapper.isStructuralValidationValid());
                assertFalse(Utils.isCollectionEmpty(signatureWrapper.getStructuralValidationMessages()));
                assertEquals(1, Utils.collectionSize(signatureWrapper.getStructuralValidationMessages()));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("/1/268/0/.cbor"));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("'7'"));
                masterSigFound = true;

            } else {
                assertFalse(signatureWrapper.isStructuralValidationValid());
                assertFalse(Utils.isCollectionEmpty(signatureWrapper.getStructuralValidationMessages()));
                assertEquals(1, Utils.collectionSize(signatureWrapper.getStructuralValidationMessages()));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("/0/.cbor/262/0/1/1"));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("#6.32"));
                counterSigFound = true;
            }
        }
        assertTrue(masterSigFound);
        assertTrue(counterSigFound);
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void validateETSISignersDocument(SignersDocumentType signersDocument) {
        // skip
    }

}
