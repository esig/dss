package eu.europa.esig.dss.evidencerecord.common.validation.identifier;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.DigestValueGroup;
import eu.europa.esig.dss.model.DSSException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Builds an {@code eu.europa.esig.dss.model.identifier.Identifier}
 * for an {@code eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord}
 *
 */
public class EvidenceRecordIdentifierBuilder {

    /** Evidence record to build identifier for */
    private final DefaultEvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link DefaultEvidenceRecord}
     */
    public EvidenceRecordIdentifierBuilder(DefaultEvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Builds an {@code EvidenceRecordIdentifier}
     *
     * @return {@link EvidenceRecordIdentifier}
     */
    public EvidenceRecordIdentifier build() {
        return new EvidenceRecordIdentifier(buildBinaries());
    }

    /**
     * Builds unique binary data describing the signature object
     *
     * @return a byte array
     */
    protected byte[] buildBinaries() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            List<? extends ArchiveTimeStampChainObject> archiveTimeStampSequence = evidenceRecord.getArchiveTimeStampSequence();
            ArchiveTimeStampChainObject archiveTimeStampChainObject = archiveTimeStampSequence.get(0);
            List<? extends ArchiveTimeStampObject> archiveTimeStamps = archiveTimeStampChainObject.getArchiveTimeStamps();
            ArchiveTimeStampObject archiveTimeStampObject = archiveTimeStamps.get(0);
            List<? extends DigestValueGroup> hashTree = archiveTimeStampObject.getHashTree();
            DigestValueGroup digestValueGroup = hashTree.get(0);
            for (byte[] binaries : digestValueGroup.getDigestValues()) {
                baos.write(binaries);
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
