package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1ArchiveTimeStampSequenceDigestHelper;
import eu.europa.esig.dss.evidencerecord.asn1.digest.ASN1EvidenceRecordDataObjectDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.evidencerecord.digest.DataObjectDigestBuilder;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Verifies ArchiveTimeStampSequence for an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordTimeStampSequenceVerifier extends EvidenceRecordTimeStampSequenceVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordTimeStampSequenceVerifier.class);

    /**
     * Default constructor to instantiate an ASN.1 evidence record verifier
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord} XML evidence record to be validated
     */
    public ASN1EvidenceRecordTimeStampSequenceVerifier(ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected DataObjectDigestBuilder getDataObjectDigestBuilder(DSSDocument document, ArchiveTimeStampChainObject archiveTimeStampChain) {
        DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();
        return new ASN1EvidenceRecordDataObjectDigestBuilder(document, digestAlgorithm);
    }

    /**
     * This method returns a document with matching {@code Digest} from a provided list of {@code detachedContents}
     *
     * @param digest {@link Digest} to check
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} defines configuration for validation
     * @param lastTimeStampSequenceHash {@link DSSMessageDigest} hash of the last archive time-stamp sequence
     * @return {@link DSSDocument} if matching document found, NULL otherwise
     */
    @Override
    protected DSSDocument getMatchingDocument(Digest digest, ArchiveTimeStampChainObject archiveTimeStampChain,
                                              DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedContents) {
        if (lastTimeStampSequenceHash.isEmpty()) {
            return super.getMatchingDocument(digest, archiveTimeStampChain, lastTimeStampSequenceHash, detachedContents);

        } else if (Utils.isCollectionNotEmpty(detachedContents)) {
            for (DSSDocument document : detachedContents) {
                DSSMessageDigest chainAndDocumentHash = getEvidenceRecordRenewalDigestBuilderHelper()
                        .computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
                byte[] documentDigest = chainAndDocumentHash.getValue();
                if (Arrays.equals(digest.getValue(), documentDigest)) {
                    return document;
                }
            }
        }
        return null;
    }
    
    @Override
    protected boolean checkHashTreeValidity(ArchiveTimeStampObject archiveTimeStamp, ArchiveTimeStampChainObject archiveTimeStampChain) {
        ASN1ArchiveTimeStampObject asn1ArchiveTimeStampObject = (ASN1ArchiveTimeStampObject) archiveTimeStamp;
        if (asn1ArchiveTimeStampObject.getDigestAlgorithm() != archiveTimeStampChain.getDigestAlgorithm()) {
            LOG.warn("The DigestAlgorithm '{}' found in ArchiveTimeStamp does not correspond to the DigestAlgorithm " +
                            "within the old Archive Timestamp '{}'! Unable to ensure validity of referenced content.",
                    asn1ArchiveTimeStampObject.getDigestAlgorithm().getName(), archiveTimeStampChain.getDigestAlgorithm().getName());
            return false;
        }
        return true;
    }

    @Override
    protected DSSMessageDigest computeTimeStampHash(ArchiveTimeStampObject archiveTimeStamp) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildTimeStampRenewalDigest(archiveTimeStamp);
    }

    @Override
    protected DSSMessageDigest computeTimeStampSequenceHash(ArchiveTimeStampChainObject archiveTimeStampChain) {
        return getEvidenceRecordRenewalDigestBuilderHelper().buildArchiveTimeStampSequenceDigest(archiveTimeStampChain);
    }

    @Override
    protected List<ReferenceValidation> validateArchiveTimeStampSequenceDigest(List<ReferenceValidation> referenceValidations,
                                                                               DSSMessageDigest lastTimeStampSequenceHashes) {
        // ASN.1 use a concatenation (archiveTimeStampSequenceHash || documentHash). No additional entry is required.
        return referenceValidations;
    }

    @Override
    protected List<byte[]> getLastTimeStampSequenceHashList(
            DSSMessageDigest lastTimeStampSequenceHash, List<DSSDocument> detachedDocuments) {
        if (Utils.isCollectionEmpty(detachedDocuments)) {
            return super.getLastTimeStampSequenceHashList(lastTimeStampSequenceHash, detachedDocuments);
        }
        final List<byte[]> hashes = new ArrayList<>();
        for (DSSDocument document : detachedDocuments) {
            DSSMessageDigest documentMessageDigest = getEvidenceRecordRenewalDigestBuilderHelper().
                    computeChainAndDocumentHash(lastTimeStampSequenceHash, document);
            hashes.add(documentMessageDigest.getValue());
        }
        return hashes;
    }

    /**
     * This method returns a helper class containing supporting methods for digest computation in relation
     * to an archive-time-stamp-sequence
     *
     * @return {@link ASN1ArchiveTimeStampSequenceDigestHelper}
     */
    protected ASN1ArchiveTimeStampSequenceDigestHelper getEvidenceRecordRenewalDigestBuilderHelper() {
        return new ASN1ArchiveTimeStampSequenceDigestHelper((ASN1EvidenceRecord) evidenceRecord);
    }

}
