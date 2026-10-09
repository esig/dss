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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.cbades.validation.AbstractCBAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESCoseSignNestedCounterSignatureArrayTest extends AbstractCBAdESTestValidation {

    private CBAdESService service;
    private DSSDocument signedDocument;
    private CBAdESCounterSignatureParameters counterSignatureParameters;

    @BeforeEach
    void init() {
        signedDocument = new FileDocument("src/test/resources/validation/cb-ades-cosesign-countersignature-rfc8152-array.cose");

        service = new CBAdESService(getCompleteCertificateVerifier());

        counterSignatureParameters = new CBAdESCounterSignatureParameters();
        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSigningCertificate(getSigningCert());
        counterSignatureParameters.setCertificateChain(getCertificateChain());
        counterSignatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
    }

    @Test
    @Override
    public void validate() {
        DocumentValidator validator = getValidator(signedDocument);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        AdvancedSignature advancedSignature = signatures.get(0);
        List<AdvancedSignature> counterSignatures = advancedSignature.getCounterSignatures();
        assertEquals(2, counterSignatures.size());

        AdvancedSignature counterSignature = counterSignatures.get(0);
        assertNotNull(counterSignature.getMasterSignature());
        assertEquals(0, counterSignature.getCounterSignatures().size());

        counterSignatureParameters.bLevel().setSigningDate(new Date());
        counterSignatureParameters.setSignatureIdToCounterSign(counterSignature.getId());

        ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument nestedCounterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);

        validator = getValidator(nestedCounterSignedSignature);

        signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        advancedSignature = signatures.get(0);
        counterSignatures = advancedSignature.getCounterSignatures();
        assertEquals(2, counterSignatures.size());

        counterSignature = counterSignatures.get(0);
        assertNotNull(counterSignature.getMasterSignature());
        assertEquals(1, counterSignature.getCounterSignatures().size());

        counterSignature = counterSignatures.get(1);
        assertNotNull(counterSignature.getMasterSignature());
        assertEquals(0, counterSignature.getCounterSignatures().size());

        Reports reports = verify(nestedCounterSignedSignature);
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
        assertEquals(4, signatureWrappers.size());

        boolean rootSignatureFound = false;
        boolean counterSignatureFound = false;
        boolean nestedCounterSignatureFound = false;
        for (SignatureWrapper signatureWrapper : signatureWrappers) {
            if (!signatureWrapper.isCounterSignature()) {
                rootSignatureFound = true;
            } else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() == null) {
                counterSignatureFound = true;
            } else if (signatureWrapper.getParent() != null && signatureWrapper.getParent().getParent() != null) {
                nestedCounterSignatureFound = true;
            }
        }
        assertTrue(rootSignatureFound);
        assertTrue(counterSignatureFound);
        assertTrue(nestedCounterSignatureFound);
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(4, signatures.size());

        int masterSigCounter = 0;
        int counterSigCounter = 0;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (!signatureWrapper.isCounterSignature()) {
                assertFalse(signatureWrapper.isStructuralValidationValid());
                assertFalse(Utils.isCollectionEmpty(signatureWrapper.getStructuralValidationMessages()));
                assertEquals(1, Utils.collectionSize(signatureWrapper.getStructuralValidationMessages()));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("/1/268/0/.cbor"));
                assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("'7'"));
                ++masterSigCounter;

            } else {
                assertTrue(signatureWrapper.isStructuralValidationValid());
                assertTrue(Utils.isCollectionEmpty(signatureWrapper.getStructuralValidationMessages()));
                ++counterSigCounter;
            }
        }
        assertEquals(1, masterSigCounter);
        assertEquals(3, counterSigCounter);
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return null;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
