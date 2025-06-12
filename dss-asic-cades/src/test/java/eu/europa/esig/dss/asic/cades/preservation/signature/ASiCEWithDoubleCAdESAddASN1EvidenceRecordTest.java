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
package eu.europa.esig.dss.asic.cades.preservation.signature;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlMessage;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithDoubleCAdESAddASN1EvidenceRecordTest extends AbstractASiCWithCAdESAddEvidenceRecordTest {

    private String signatureId = null;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-two-sigs.sce");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-cades-lt-two-sigs.ers");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        int sigWithErCounter = 0;
        int sigWithoutErCounter = 0;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
                assertEquals(1, Utils.collectionSize(signature.getEvidenceRecords()));
                for (EvidenceRecordWrapper evidenceRecordWrapper : signature.getEvidenceRecords()) {
                    assertEquals(signatureId, evidenceRecordWrapper.getParent().getId());
                }
                checkEvidenceRecordCoverage(diagnosticData, signature);
                ++sigWithErCounter;
            } else {
                ++sigWithoutErCounter;
            }
        }
        assertEquals(1, sigWithErCounter);
        assertEquals(1, sigWithoutErCounter);
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        super.checkEvidenceRecordCoverage(diagnosticData, signature);

        if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
            int erCoveringERCounter = 0;
            int erNotCoveringERCounter = 0;
            for (EvidenceRecordWrapper evidenceRecordWrapper : signature.getEvidenceRecords()) {
                if (Utils.isCollectionNotEmpty(evidenceRecordWrapper.getCoveredEvidenceRecords())) {
                    ++erCoveringERCounter;
                } else {
                    ++erNotCoveringERCounter;
                }
            }
            assertEquals(0, erCoveringERCounter);
            assertEquals(1, erNotCoveringERCounter);
        }
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean cadesLTFound = false;
        boolean cadesERSFound = false;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_LT == signature.getSignatureFormat()) {
                cadesLTFound = true;
            } else if (SignatureLevel.CAdES_ERS == signature.getSignatureFormat()) {
                cadesERSFound = true;
            }
        }
        assertTrue(cadesLTFound);
        assertTrue(cadesERSFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestampWrapper : timestampList) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            assertTrue(Utils.isCollectionNotEmpty(timestamps));
            for (TimestampWrapper timestampWrapper : timestamps) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
            }
        }
    }

    @Override
    protected int getNumberOfCoveredDocuments() {
        return 3;
    }

    @Override
    protected CAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        CAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setSignatureId(signatureId);
        return parameters;
    }

    @Test
    @Override
    public void addERAndValidate() {
        ASiCWithCAdESService service = getService();

        Exception exception = assertThrows(IllegalArgumentException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("More than one signature found in a document! " +
                "Please provide a signatureId within the parameters.", exception.getMessage());

        signatureId = "not-existing";
        exception = assertThrows(IllegalArgumentException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("A signature with id 'not-existing' has not been found!", exception.getMessage());

        SignedDocumentValidator validator = getValidator(getSignatureDocument());
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(2, signatures.size());

        // first signature
        signatureId = signatures.get(0).getId();
        DSSDocument signatureWithER = service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());
        verify(signatureWithER);

        // second signature
        signatureId = signatures.get(1).getId();
        exception = assertThrows(IllegalInputException.class, () ->
                service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters()));
        assertEquals("The digest covered by the evidence record do not correspond to the digest computed on the signature!", exception.getMessage());
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        boolean sigWithERFound = false;
        boolean sigWithoutERFound = false;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                assertEquals(1, signatureEvidenceRecords.size());

                XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
                XmlDetails adesValidationDetails = evidenceRecord.getAdESValidationDetails();

                boolean originalFilesCoveredCheckFound = false;
                for (XmlMessage xmlMessage : adesValidationDetails.getWarning()) {
                    if (MessageTag.BBB_FC_ISFP_ASTFORAMC_ANS.getId().equals(xmlMessage.getKey())) {
                        originalFilesCoveredCheckFound = true;
                        break;
                    }
                }
                assertTrue(originalFilesCoveredCheckFound);

                sigWithERFound = true;

            } else {
                sigWithoutERFound = true;
            }
        }
        assertTrue(sigWithERFound);
        assertTrue(sigWithoutERFound);
    }

}
