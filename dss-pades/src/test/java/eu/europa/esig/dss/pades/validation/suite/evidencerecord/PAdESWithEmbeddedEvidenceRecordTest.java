package eu.europa.esig.dss.pades.validation.suite.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESWithEmbeddedEvidenceRecordTest extends AbstractPAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/evidence-record/PAdES_with_er.pdf"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.PAdES_BES, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 3;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        assertEquals(1, diagnosticData.getEvidenceRecords().size());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertEquals(3, evidenceRecordWrapper.getDigestMatchers().size());

        int masterSigDMCounter = 0;
        int arcObjDMCounter = 0;
        int orphanRefDMCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : evidenceRecordWrapper.getDigestMatchers()) {
            if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == xmlDigestMatcher.getType()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
                ++masterSigDMCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                assertTrue(xmlDigestMatcher.isDataFound());
                assertTrue(xmlDigestMatcher.isDataIntact());
                ++arcObjDMCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == xmlDigestMatcher.getType()) {
                assertFalse(xmlDigestMatcher.isDataFound());
                assertFalse(xmlDigestMatcher.isDataIntact());
                ++orphanRefDMCounter;
            }
        }
        assertEquals(1, masterSigDMCounter);
        assertEquals(1, arcObjDMCounter);
        assertEquals(1, orphanRefDMCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordScopes(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(3, evidenceRecordScopes.size());

        boolean cmsDocFound = false;
        boolean pdfDocFound = false;
        boolean masterSigFound = false;
        for (XmlSignatureScope signatureScope : evidenceRecordScopes) {
            if (SignatureScopeType.SIGNATURE == signatureScope.getScope()) {
                masterSigFound = true;
            } else if (SignatureScopeType.FULL == signatureScope.getScope()) {
                if (signatureScope.getDescription().contains("ByteRange")) {
                    pdfDocFound = true;
                } else {
                    cmsDocFound = true;
                }
            }
        }
        assertTrue(cmsDocFound);
        assertTrue(pdfDocFound);
        assertTrue(masterSigFound);
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

}
