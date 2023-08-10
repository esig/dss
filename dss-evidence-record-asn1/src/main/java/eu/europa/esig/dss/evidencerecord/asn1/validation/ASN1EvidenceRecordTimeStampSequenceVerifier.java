package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSMessageDigest;

/**
 * Verifies ArchiveTimeStampSequence for an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordTimeStampSequenceVerifier extends EvidenceRecordTimeStampSequenceVerifier {

    /**
     * Default constructor to instantiate an ASN.1 evidence record verifier
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord} XML evidence record to be validated
     */
    public ASN1EvidenceRecordTimeStampSequenceVerifier(ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        // TODO : to be implemented
        return null;
    }

    @Override
    protected DSSMessageDigest computePrecedingTimeStampSequenceHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampChainObject archiveTimeStampChain) {
        // TODO : to be implemented
        return null;
    }

}
