package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCEWithCAdESLevelBAddContainerXMLEvidenceRecordTest extends AbstractASiCWithCAdESTestAddContainerEvidenceRecord {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/signable/asic_cades.zip"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-asic_cades-signature-and-manifest-and-data.xml");
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);

        int archiveDataObjectCounter = 0;
        int orphanDataObjectCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecordWrapper.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                ++archiveDataObjectCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                ++orphanDataObjectCounter;
            }
        }
        assertEquals(3, archiveDataObjectCounter);
        assertEquals(0, orphanDataObjectCounter);
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 3;
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        super.checkEvidenceRecordCoverage(diagnosticData, signature);

        List<EvidenceRecordWrapper> signatureEvidenceRecords = signature.getEvidenceRecords();
        assertEquals(1, Utils.collectionSize(signatureEvidenceRecords));

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, Utils.collectionSize(evidenceRecords));

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(2, evidenceRecordWrapper.getCoveredSignedData().size());
        assertEquals(1, evidenceRecordWrapper.getCoveredSignatures().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredTimestamps().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredEvidenceRecords().size());
        assertEquals(2, evidenceRecordWrapper.getCoveredCertificates().size());
        assertEquals(0, evidenceRecordWrapper.getCoveredRevocations().size());
    }

}
