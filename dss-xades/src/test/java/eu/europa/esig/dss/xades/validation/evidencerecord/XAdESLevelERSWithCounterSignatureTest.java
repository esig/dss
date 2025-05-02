package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelERSWithCounterSignatureTest extends AbstractXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-with-counter-sig.xml");
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        return trustedCertificateSource;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);

        assertEquals(2, diagnosticData.getSignatures().size());
        assertEquals(1, diagnosticData.getAllSignatures().size());
        assertEquals(1, diagnosticData.getAllCounterSignatures().size());

        boolean masterSigFound = false;
        boolean counterSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                counterSigFound = true;
            } else {
                masterSigFound = true;
            }
        }
        assertTrue(masterSigFound);
        assertTrue(counterSigFound);
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean masterSigFound = false;
        boolean counterSigFound = false;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (signatureWrapper.isCounterSignature()) {
                assertEquals(SignatureLevel.XAdES_BASELINE_LT, signatureWrapper.getSignatureFormat());
                counterSigFound = true;
            } else {
                assertEquals(SignatureLevel.XAdES_ERS, signatureWrapper.getSignatureFormat());
                masterSigFound = true;
            }
        }
        assertTrue(masterSigFound);
        assertTrue(counterSigFound);
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecords) || signature.isCounterSignature());

        if (Utils.isCollectionNotEmpty(evidenceRecords)) {
            EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);

            assertEquals(2, evidenceRecord.getCoveredSignatures().size());
            assertEquals(3, evidenceRecord.getCoveredSignedData().size());
            assertEquals(10, evidenceRecord.getCoveredCertificates().size());
            assertEquals(4, evidenceRecord.getCoveredRevocations().size());
            assertEquals(2, evidenceRecord.getCoveredTimestamps().size());
        }
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(2, evidenceRecord.getEvidenceRecordScopes().size());

        int sigScopeCounter = 0;
        int dataScopeCounter = 0;
        for (XmlSignatureScope signatureScope : evidenceRecord.getEvidenceRecordScopes()) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                assertEquals(evidenceRecord.getParent().getId(), signatureScope.getName());
                ++sigScopeCounter;
            } else if (SignatureScopeType.PARTIAL == signatureScope.getScope()) {
                assertNotNull(signatureScope.getName());
                ++dataScopeCounter;
            }
        }
        assertEquals(1, sigScopeCounter);
        assertEquals(1, dataScopeCounter);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertNotNull(timestampWrapper.getProductionTime());
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureValid());
        }
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        int sigWithErCounter = 0;
        int sigWithoutErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            } else {
                ++sigWithoutErCounter;
            }
        }
        assertEquals(1, sigWithErCounter);
        assertEquals(1, sigWithoutErCounter);
    }

}