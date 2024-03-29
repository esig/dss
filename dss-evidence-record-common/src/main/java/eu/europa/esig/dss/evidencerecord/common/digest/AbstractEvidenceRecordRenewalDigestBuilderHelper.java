package eu.europa.esig.dss.evidencerecord.common.digest;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;

import java.util.List;

/**
 * Abstract class containing common supporting methods for evidence record digest calculation
 *
 */
public abstract class AbstractEvidenceRecordRenewalDigestBuilderHelper {

    /**
     * Evidence record to compute digest for
     */
    protected final DefaultEvidenceRecord evidenceRecord;

    /**
     * Creates an instance of {@code AbstractEvidenceRecordRenewalDigestBuilderHelper} allowing to build hash for
     * {@code XmlEvidenceRecord}'s renewal.
     * Builds digest for the last available ArchiveTimeStamp or ArchiveTimeStampChain, based on the called method.
     *
     * @param evidenceRecord {@link DefaultEvidenceRecord}
     */
    protected AbstractEvidenceRecordRenewalDigestBuilderHelper(final DefaultEvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Returns an {@code ArchiveTimeStampChainObject} corresponding to the given {@code archiveTimeStampObject}
     *
     * @param archiveTimeStampObject {@link ArchiveTimeStampObject} to get {@code ArchiveTimeStampChainObject} for
     * @return {@link ArchiveTimeStampChainObject}
     */
    protected ArchiveTimeStampChainObject getArchiveTimeStampChainObject(ArchiveTimeStampObject archiveTimeStampObject) {
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        for (ArchiveTimeStampChainObject archiveTimeStampChain : archiveTimeStampSequence) {
            for (ArchiveTimeStampObject archiveTimeStamp : archiveTimeStampChain.getArchiveTimeStamps()) {
                if (archiveTimeStampObject.equals(archiveTimeStamp)) {
                    return archiveTimeStampChain;
                }
            }
        }
        throw new IllegalArgumentException("Unable to find a corresponding ArchiveTimeStampChain for the given ArchiveTimeStamp!");
    }

    /**
     * This method builds digest for a time-stamp renewal using a digest algorithm from the
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to build digest on
     * @return {@link Digest}
     */
    public abstract DSSMessageDigest buildTimeStampRenewalDigest(ArchiveTimeStampObject archiveTimeStamp);

    /**
     * Builds digest for renewal of the hash-tree, considering the provided {@code archiveTimeStampChainObject}
     * as the last chain in the evidence record.
     * Note: this method build digest solely for {@code ArchiveTimeStampChainObject} without considering
     *       detached content. Please use {@code #buildHashTreeRenewalDigestGroup} method instead fo hash calculation
     *       in case of a hash-tree renewal with a new time-stamp
     *
     * @return {@link DSSMessageDigest}
     */
    public abstract DSSMessageDigest buildArchiveTimeStampSequenceDigest(ArchiveTimeStampChainObject archiveTimeStampChain);

    /**
     * Returns the next chronologically ordered {@code ArchiveTimeStampChainObject}
     *
     * @param archiveTimeStampChainObject {@link ArchiveTimeStampChainObject} to get a parent for
     * @return {@link ArchiveTimeStampChainObject}
     */
    protected ArchiveTimeStampChainObject getNextArchiveTimeStampChain(ArchiveTimeStampChainObject archiveTimeStampChainObject) {
        int order = archiveTimeStampChainObject.getOrder();
        List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
        for (ArchiveTimeStampChainObject archiveTimeStampChain : archiveTimeStampSequence) {
            if (archiveTimeStampChain.getOrder() == order + 1) {
                return archiveTimeStampChain;
            }
        }
        // new hash-tree renewal computation
        return null;
    }

}
