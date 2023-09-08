package eu.europa.esig.dss.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ManifestFile;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;

import java.util.List;

/**
 * Representation of an Evidence Record
 *
 */
public interface EvidenceRecord extends IdentifierBasedObject {

    /**
     * Returns a name of the evidence record document, when present
     *
     * @return {@link String}
     */
    String getFilename();

    /**
     * Returns a list of archive data object validations
     *
     * @return a list of {@link ReferenceValidation} objects corresponding to each archive data object validation
     */
    List<ReferenceValidation> getReferenceValidation();

    /**
     * Returns detached contents
     *
     * @return in the case of the detached signature this is the {@code List} of signed contents.
     */
    List<DSSDocument> getDetachedContents();

    /**
     * Returns a list of incorporated timestamp tokens
     *
     * @return a list of {@link TimestampToken}s
     */
    List<TimestampToken> getTimestamps();

    /**
     * Returns a list of detached evidence records covering the current evidence record.
     *
     * @return a list of {@link EvidenceRecord}s
     */
    List<EvidenceRecord> getDetachedEvidenceRecords();

    /**
     * This method allows to add an external evidence record covering the current evidence record.
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    void addExternalEvidenceRecord(EvidenceRecord evidenceRecord);

    /**
     * Returns a list of covered archival data objects
     *
     * @return a list of {@link SignatureScope}s
     */
    List<SignatureScope> getEvidenceRecordScopes();

    /**
     * Sets a list of covered archival data objects
     *
     * @param evidenceRecordScopes a list of {@link SignatureScope}s
     */
    void setEvidenceRecordScopes(List<SignatureScope> evidenceRecordScopes);

    /**
     * Returns a message if the structure validation fails
     *
     * @return a list of {@link String} error messages if validation fails,
     *         an empty list if structural validation succeeds
     */
    List<String> getStructureValidationResult();

    /**
     * Returns type of the evidence record
     *
     * @return {@link EvidenceRecordTypeEnum}
     */
    EvidenceRecordTypeEnum getReferenceRecordType();

    /**
     * Returns a manifest file associated with the evidence record (used in ASiC)
     *
     * @return {@link ManifestFile}
     */
    ManifestFile getManifestFile();

    /**
     * Returns a list of references covered by the evidence record
     *
     * @return a list of {@link TimestampedReference}s
     */
    List<TimestampedReference> getTimestampedReferences();

    /**
     * Sets references to objects covered by the evidence record
     *
     * @param timestampedReferences a list of {@link TimestampedReference}s
     */
    void setTimestampedReferences(List<TimestampedReference> timestampedReferences);

    /**
     * This method returns the DSS unique signature id. It allows to unambiguously identify each signature.
     *
     * @return The signature unique Id
     */
    String getId();

}
