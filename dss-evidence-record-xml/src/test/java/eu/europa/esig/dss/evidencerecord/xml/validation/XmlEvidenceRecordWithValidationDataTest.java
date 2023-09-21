package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XmlEvidenceRecordWithValidationDataTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-simple-validation-data.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "dCeyHarzzN3cWzVNTMKZyY00rW4gNGGto/2ZLfzpsXM="));
    }

    @Override
    protected void checkEvidenceRecordValidationData(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordValidationData(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        FoundCertificatesProxy foundCertificates = evidenceRecordWrapper.foundCertificates();
        assertEquals(2, Utils.collectionSize(foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundCertificates.getRelatedCertificateRefs()));
        assertEquals(0, Utils.collectionSize(foundCertificates.getOrphanCertificateRefs()));

        FoundRevocationsProxy foundRevocations = evidenceRecordWrapper.foundRevocations();
        assertEquals(1, Utils.collectionSize(foundRevocations.getRelatedRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getRelatedRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getOrphanRevocationsByTypeAndOrigin(RevocationType.CRL, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(1, Utils.collectionSize(foundRevocations.getOrphanRevocationsByTypeAndOrigin(RevocationType.OCSP, RevocationOrigin.EVIDENCE_RECORD)));
        assertEquals(0, Utils.collectionSize(foundRevocations.getRelatedRevocationRefs()));
        assertEquals(0, Utils.collectionSize(foundRevocations.getOrphanRevocationRefs()));
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanCertificateObjects())); // cert is coming from orphan OCSP
        assertEquals(1, Utils.collectionSize(diagnosticData.getAllOrphanRevocationObjects()));
    }

}
