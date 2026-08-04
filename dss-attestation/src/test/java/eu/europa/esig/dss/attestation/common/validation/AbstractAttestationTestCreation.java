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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.attestation.common.creation.AttestationPayloadParameters;
import eu.europa.esig.dss.attestation.common.creation.AttestationService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractAttestationTestCreation<SP extends SerializableSignatureParameters, B extends AttestationPayloadParameters> extends AbstractAttestationPresentationTestValidation {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractAttestationTestCreation.class);

    protected abstract B getPayloadParameters();

    protected abstract SP getSignatureParameters();

    protected abstract AttestationService<SP, B> getService();

    protected abstract MimeType getExpectedMime();

    private DSSDocument signedAttestation;

    @Test
    public void signAndVerify() {
        final DSSDocument attestation = getSignedDocument();

        assertNotNull(attestation.getName());
        assertNotNull(attestation.getMimeType());

        // attestation.save("target/" + attestationPresentation.getName());

        byte[] byteArray = DSSUtils.toByteArray(attestation);
        onDocumentSigned(byteArray);
        if (LOG.isDebugEnabled()) {
            LOG.debug(new String(byteArray));
        }

        checkMimeType(attestation);

        verify(attestation);
    }

    @Override
    public void validate() {
        // skip
    }

    protected DSSDocument signAttestation() {
        if (signedAttestation == null) {
            B payloadParameters = getPayloadParameters();
            SP params = getSignatureParameters();
            AttestationService<SP, B> service = getService();

            ToBeSigned dataToSign = service.getDataToSign(payloadParameters, params);
            SignatureValue signatureValue = getToken().sign(dataToSign, params.getSignatureAlgorithm(), getPrivateKeyEntry());
            // TODO : add signature verification ?
            signedAttestation = service.signAttestation(payloadParameters, params, signatureValue);
        }
        return signedAttestation;
    }

    @Override
    protected DSSDocument getSignedDocument() {
        return signAttestation();
    }

    protected void checkMimeType(DSSDocument signedDocument) {
        assertEquals(getExpectedMime(), signedDocument.getMimeType());
    }

    protected void onDocumentSigned(byte[] byteArray) {
        assertTrue(Utils.isArrayNotEmpty(byteArray));
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        int expectedSignaturesCount = keyBindingPresent() ? 2 : 1;
        assertEquals(expectedSignaturesCount, signatures.size());
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        int expectedSignaturesCount = keyBindingPresent() ? 2 : 1;
        assertEquals(expectedSignaturesCount, signatures.size());

        int attestationSignatureCount = 0;
        int keyBindingSignatureCount = 0;
        for (SignatureWrapper signatureWrapper : signatures) {
            if (signatureWrapper.isKeyBindingSignature()) {
                ++keyBindingSignatureCount;
            } else {
                ++attestationSignatureCount;
            }
        }
        assertEquals(1, attestationSignatureCount);
        assertEquals(expectedSignaturesCount - 1, keyBindingSignatureCount);
    }

    protected int getNumberOfOrphanSDClaims() {
        return getPayloadParameters().getDecoyDigestNumber();
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
            SignatureWrapper signature = diagnosticData.getSignatureById(signatureValidationReport.getSignatureIdentifier().getId());

            SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
            assertNotNull(signatureIdentifier);

            assertNotNull(signatureIdentifier.getSignatureValue());
            assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
        }
    }

    @Override
    protected boolean orphanSelectiveDisclosuresPresent() {
        return getPayloadParameters().getDecoyDigestNumber() > 0;
    }

}
