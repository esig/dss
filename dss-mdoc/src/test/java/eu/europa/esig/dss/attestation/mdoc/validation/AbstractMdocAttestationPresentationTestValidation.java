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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAADocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPresentationInfo;
import eu.europa.esig.dss.attestation.common.validation.AbstractAttestationPresentationTestValidation;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.AttestationPresentationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractMdocAttestationPresentationTestValidation extends AbstractAttestationPresentationTestValidation {

    @Override
    protected AttestationFormat getEAAType() {
        return AttestationFormat.ISO_IEC_MDOC;
    }

    @Override
    protected AttestationPresentationType getEAAPresentationType() {
        if (keyBindingPresent()) {
            return AttestationPresentationType.MDOC_DEVICE_RESPONSE;
        } else {
            return AttestationPresentationType.MDOC_ISSUER_SIGNED;
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        if (keyBindingPresent()) {
            MdocDeviceResponseAttestationDocumentValidator mdocValidator = assertInstanceOf(MdocDeviceResponseAttestationDocumentValidator.class, validator);
            MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
            mdocValidationParameters.setSessionTranscript(getSessionTranscript());
            mdocValidator.setEAAValidationParameters(mdocValidationParameters);
        }
        return validator;
    }

    protected DSSDocument getSessionTranscript() {
        throw new NullPointerException("SessionTranscript was not provided!");
    }

    @Override
    protected void checkEAAPresentationInfo(DiagnosticData diagnosticData) {
        super.checkEAAPresentationInfo(diagnosticData);

        XmlEAAPresentationInfo attestationPresentationInfo = diagnosticData.getEAAPresentationInfo();
        if (AttestationPresentationType.MDOC_DEVICE_RESPONSE == attestationPresentationInfo.getEAAPresentationType()) {
            assertEquals("1.0", attestationPresentationInfo.getVersion());
            assertNull(attestationPresentationInfo.getErrors());
            assertNotNull(attestationPresentationInfo.getStatus());
            assertEquals(0, attestationPresentationInfo.getStatus().intValue());
        }

        for (XmlEAADocument xmlEAADocument : attestationPresentationInfo.getDocuments()) {
            switch (attestationPresentationInfo.getEAAPresentationType()) {
                case MDOC_DEVICE_RESPONSE:
                    assertNotNull(xmlEAADocument.getDocumentType());
                    break;
                case MDOC_ISSUER_SIGNED:
                    assertNull(xmlEAADocument.getDocumentType());
                    break;
                default:
                    fail(String.format("Not supported Attestation Presentation type : %s", attestationPresentationInfo.getEAAPresentationType()));
            }

            assertTrue(Utils.isCollectionEmpty(xmlEAADocument.getErrors()));
        }
    }

    @Override
    protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertNotNull(signatureWrapper.getSignatureValue());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isKeyBindingSignature()) {
                assertTrue(signatureWrapper.isSigningCertificateIdentified());
                assertTrue(signatureWrapper.isSigningCertificateReferencePresent());

                CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
                assertNotNull(signingCertificateReference);
                assertTrue(signingCertificateReference.isDigestValuePresent());
                assertTrue(signingCertificateReference.isDigestValueMatch());
                if (signingCertificateReference.isIssuerSerialPresent()) {
                    assertTrue(signingCertificateReference.isIssuerSerialMatch());
                }

                CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
                assertNotNull(signingCertificate);
                String signingCertificateId = signingCertificate.getId();
                String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
                String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
                assertEquals(signingCertificate.getCertificateDN(), certificateDN);
                assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                        .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            } else {
                assertTrue(signatureWrapper.getSigningCertificate() != null || signatureWrapper.getSigningCertificatePublicKey() != null);
            }

        }
    }

    @Override
    protected void checkCOSESignatureType(DiagnosticData diagnosticData) {
        super.checkCOSESignatureType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertEquals(COSESignatureType.COSE_SIGN1, signatureWrapper.getCOSESignatureType());
        }
    }

    @Override
    protected void checkReportsSignatureIdentifier(Reports reports) {
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
        for (SignatureValidationReportType signatureValidationReport : etsiValidationReport.getSignatureValidationReport()) {
            SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
            assertNotNull(signatureIdentifier);
            assertNotNull(signatureIdentifier.getSignatureValue());

            SignatureWrapper signature = diagnosticData.getSignatureById(signatureIdentifier.getId());
            assertArrayEquals(signature.getSignatureValue(), signatureIdentifier.getSignatureValue().getValue());
        }
    }

}
