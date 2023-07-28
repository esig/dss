package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ByteArrayComparator;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecord;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Builds a time-stamp message-imprint for time-stamp's validation
 *
 */
public abstract class EvidenceRecordTimestampMessageDigestBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordTimestampMessageDigestBuilder.class);

    /** The EvidenceRecord to be validated */
    protected final EvidenceRecord evidenceRecord;

    /** The element to be validated */
    protected final ArchiveTimeStampObject archiveTimeStampObject;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord} representing the evidence record document
     * @param archiveTimeStampObject {@link ArchiveTimeStampObject} to be validated
     */
    protected EvidenceRecordTimestampMessageDigestBuilder(final EvidenceRecord evidenceRecord,
                                                          final ArchiveTimeStampObject archiveTimeStampObject) {
        this.evidenceRecord = evidenceRecord;
        this.archiveTimeStampObject = archiveTimeStampObject;
    }

    /**
     * Gets a message-imprint for validation of a time-stamp token
     *
     * @return {@link DSSMessageDigest}
     */
    public DSSMessageDigest getArchiveTimestampMessageDigest() {
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        for (int i = 0; i < archiveTimeStampSequence.size(); i++) {
            ArchiveTimeStampChainObject archiveTimeStampChain = archiveTimeStampSequence.get(i);
            DigestAlgorithm digestAlgorithm = archiveTimeStampChain.getDigestAlgorithm();

            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChain.getArchiveTimeStamps();
            for (int j = 0; j < archiveTimeStamps.size(); j++) {
                ArchiveTimeStampObject archiveTimeStamp = archiveTimeStamps.get(j);
                if (archiveTimeStampObject == archiveTimeStamp) {
                    List<? extends DigestValueGroup> hashTree = archiveTimeStamp.getHashTree();

                    if (j > 0) {
                        // compute hash for the previous timestamp entry
                        DSSMessageDigest lastTimeStampHash = computeTimeStampHash(digestAlgorithm, archiveTimeStamps.get(j - 1));
                        if (!lastTimeStampHash.isEmpty() && !containsDigest(hashTree, lastTimeStampHash)) {
                            LOG.warn("No digest matching the previous TimeStamp element found!");
                            return DSSMessageDigest.createEmptyDigest();
                        }
                    } else if (i > 0) {
                        // if first time-stamp in a next ArchiveTimeStampChain
                        DSSMessageDigest lastTimeStampSequenceHash = computeTimeStampSequenceHash(digestAlgorithm, archiveTimeStampChain);
                        if (!lastTimeStampSequenceHash.isEmpty() && !containsDigest(hashTree, lastTimeStampSequenceHash)) {
                            LOG.warn("No digest matching the previous TimeStamp element found!");
                            return DSSMessageDigest.createEmptyDigest();
                        }
                    }

                    /*
                     * 3. If the hash tree is present, calculate its root hash value.
                     * Compare the root hash value with the Time-Stamped value. If they
                     * are not equal, terminate the verification process with negative
                     * result.
                     */
                    if (Utils.isCollectionNotEmpty(hashTree)) {
                        return calculateRootHashValue(digestAlgorithm, hashTree);
                    }
                    /*
                     * 4. If the hash tree is omitted, compare the hash value of the single
                     * data object with the Time-Stamped value. If they are not equal,
                     * terminate the verification process with negative result. If an
                     * archive object is having more data objects and the hash tree is
                     * omitted, also exit with negative result.
                     */
                    else {
                        // TODO : to be implemented
                        throw new UnsupportedOperationException("Not implemented!");
                    }
                }
            }
        }

        return null;
    }

    /**
     * Computes hash on {@code archiveTimeStamp} element provided the {@code archiveTimeStampChain}'s attributes
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for hash computation
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to compute hash on
     * @return {@link DSSMessageDigest}
     */
    protected abstract DSSMessageDigest computeTimeStampHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampObject archiveTimeStamp);

    /**
     * Computes hash on {@code ArchiveTimeStampSequenceElement} using {@code archiveTimeStampChain} as the last element
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for hash computation
     * @param archiveTimeStampChain {@link ArchiveTimeStampChainObject} to compute hash for
     * @return {@link DSSMessageDigest}
     */
    protected abstract DSSMessageDigest computeTimeStampSequenceHash(DigestAlgorithm digestAlgorithm, ArchiveTimeStampChainObject archiveTimeStampChain);

    /**
     * This method verifies whether the {@code hashTree} contains the {@code messageDigest}
     *
     * @param hashTree a list of {@link DigestValueGroup}s
     * @param messageDigest {@link DSSMessageDigest} containing hash value to check
     * @return TRUE if the hashTree contains digest value, FALSE otherwise
     */
    protected boolean containsDigest(List<? extends DigestValueGroup> hashTree, DSSMessageDigest messageDigest) {
        if (hashTree.size() == 0) {
            LOG.warn("Empty HashTree encountered! Unable to validate a time-stamp.");
            return false;
        }
        // The first group should contain the value
        DigestValueGroup digestValueGroup = hashTree.get(0);
        return digestValueGroup.getDigestValues().stream().anyMatch(b -> Arrays.equals(messageDigest.getValue(), b));
    }

    /**
     * Computes a root hash value for the given {@code hashTree}
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to use for hash computation
     * @param hashTree a list of ordered {@link DigestValueGroup}s
     * @return {@link DSSMessageDigest}
     */
    protected DSSMessageDigest calculateRootHashValue(DigestAlgorithm digestAlgorithm, List<? extends DigestValueGroup> hashTree) {
        DSSMessageDigest lastMessageDigest = DSSMessageDigest.createEmptyDigest();
        for (DigestValueGroup digestValueGroup : hashTree) {
            lastMessageDigest = computeDigestValueGroupHash(digestAlgorithm, digestValueGroup, lastMessageDigest);
        }
        return lastMessageDigest;
    }

    /**
     * Computes a hash value for a group of hashes
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to be used for a hash computation
     * @param digestValueGroup {@link DigestValueGroup} containing grouped elements from a hash tree
     * @param otherObjectDigests additional hash values obtained from other computations
     * @return {@link DSSMessageDigest}
     */
    protected DSSMessageDigest computeDigestValueGroupHash(DigestAlgorithm digestAlgorithm,
            DigestValueGroup digestValueGroup, DSSMessageDigest... otherObjectDigests) {
        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are ordered in binary ascending order,
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */
        // 1. Group together items
        List<byte[]> hashValueList = new ArrayList<>(digestValueGroup.getDigestValues());
        for (DSSMessageDigest messageDigest : otherObjectDigests) {
            if (!messageDigest.isEmpty()) {
                hashValueList.add(messageDigest.getValue());
            }
        }
        // 2a. Exception
        if (Utils.collectionSize(hashValueList) == 1) {
            return new DSSMessageDigest(digestAlgorithm, hashValueList.get(0));
        }
        // 2b. Binary ascending sort
        hashValueList.sort(ByteArrayComparator.getInstance());
        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : hashValueList) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        return digestCalculator.getMessageDigest();
    }

}
