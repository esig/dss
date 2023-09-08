package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.scope.EvidenceRecordTimestampScopeFinder;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.ListRevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used for extraction and validation of time-stamps incorporated within an Evidence Record
 *
 * @param <ER> {@code DefaultEvidenceRecord}
 */
public abstract class EvidenceRecordTimestampSource<ER extends DefaultEvidenceRecord> extends AbstractTimestampSource {

    /**
     * The evidence record to be validated
     */
    protected final ER evidenceRecord;

    /**
     * CRL revocation source containing merged data from signature and timestamps
     */
    protected ListRevocationSource<CRL> crlSource;

    /**
     * OCSP revocation source containing merged data from signature and timestamps
     */
    protected ListRevocationSource<OCSP> ocspSource;

    /**
     * CertificateSource containing merged data from signature and timestamps
     */
    protected ListCertificateSource certificateSource;

    /**
     * Enclosed timestamps
     */
    protected List<TimestampToken> timestamps;

    /**
     * This variable contains the list of detached evidence record tokens covering the evidence record.
     */
    protected List<EvidenceRecord> detachedEvidenceRecords;

    /**
     * Default constructor to instantiate a time-stamp source from an evidence record
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    protected EvidenceRecordTimestampSource(ER evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "The evidence record cannot be null!");
        this.evidenceRecord = evidenceRecord;
    }

    /**
     * Returns a list of found {@code TimestampToken}s
     *
     * @return a list of {@code TimestampToken}s
     */
    public List<TimestampToken> getTimestamps() {
        if (timestamps == null) {
            createAndValidate();
        }
        return timestamps;
    }

    /**
     * Returns a list of detached evidence records covering the evidence record
     *
     * @return a list of {@link EvidenceRecord}s
     */
    public List<EvidenceRecord> getDetachedEvidenceRecords() {
        if (detachedEvidenceRecords == null) {
            createAndValidate();
        }
        return detachedEvidenceRecords;
    }

    public void addExternalEvidenceRecord(EvidenceRecord evidenceRecord) {
        // if timestamp tokens not created yet
        if (detachedEvidenceRecords == null) {
            createAndValidate();
        }
        processExternalEvidenceRecord(evidenceRecord);
        detachedEvidenceRecords.add(evidenceRecord);
    }

    /**
     * Creates and validates all timestamps
     * Must be called only once
     */
    protected void createAndValidate() {
        timestamps = new ArrayList<>();
        detachedEvidenceRecords = new ArrayList<>();

        // initialize combined revocation sources
        crlSource = new ListRevocationSource<>(); // TODO : add evidenceRecord.getCRLSource()
        ocspSource = new ListRevocationSource<>(); // TODO : evidenceRecord.getOCSPSource()
        certificateSource = new ListCertificateSource(); // TODO : evidenceRecord.getCertificateSource()

        final List<TimestampedReference> signerDataReferences = getSignerDataReferences();

        List<TimestampedReference> previousTimestampReferences = new ArrayList<>();
        List<TimestampedReference> previousChainTimestampReferences = new ArrayList<>();

        List<TimestampedReference> references = new ArrayList<>();

        for (ArchiveTimeStampChainObject archiveTimeStampChain : evidenceRecord.getArchiveTimeStampSequence()) {

            addReferences(references, signerDataReferences);
            addReference(references, getEvidenceRecordReference());
            addReferences(references, previousChainTimestampReferences);
            previousChainTimestampReferences = new ArrayList<>();

            for (ArchiveTimeStampObject archiveTimeStamp : archiveTimeStampChain.getArchiveTimeStamps()) {

                addReferences(references, previousTimestampReferences);
                previousTimestampReferences = new ArrayList<>();

                TimestampToken timestampToken = createTimestampToken(archiveTimeStamp);
                timestampToken.getTimestampedReferences().addAll(references);
                timestampToken.setTimestampScopes(findTimestampScopes(timestampToken));

                // add time-stamp token
                populateSources(timestampToken);
                timestamps.add(timestampToken);

                List<TimestampedReference> encapsulatedTimestampReferences = getEncapsulatedReferencesFromTimestamp(timestampToken);
                addReferences(previousTimestampReferences, encapsulatedTimestampReferences);
                addReferences(previousChainTimestampReferences, encapsulatedTimestampReferences);

                // clear references for the next time-stamp token
                references = new ArrayList<>();
            }

        }
    }

    /**
     * This method is used to create a {@code TimestampToken} from {@code ArchiveTimeStampObject}
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} to extract time-stamp token from
     * @return {@link TimestampToken}
     */
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp) {
        return archiveTimeStamp.getTimestampToken();
    }

    /**
     * Creates a evidence record reference for the current signature
     *
     * @return {@link TimestampedReference}
     */
    protected TimestampedReference getEvidenceRecordReference() {
        return new TimestampedReference(evidenceRecord.getId(), TimestampedObjectType.EVIDENCE_RECORD);
    }

    /**
     * Returns a list of timestamped references for signed data objects
     *
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignerDataReferences() {
        List<SignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
        if (Utils.isCollectionEmpty(evidenceRecordScopes)) {
            return Collections.emptyList();
        }
        return getSignerDataTimestampedReferences(evidenceRecordScopes);
    }

    /**
     * Returns a list of TimestampedReferences for tokens encapsulated within the time-stamp token
     *
     * @param timestampToken {@link TimestampToken} to get references from
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getEncapsulatedReferencesFromTimestamp(TimestampToken timestampToken) {
        return getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource);
    }

    /**
     * Finds timestamp scopes
     *
     * @param timestampToken {@link TimestampToken} to get timestamp scopes for
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> findTimestampScopes(TimestampToken timestampToken) {
        return new EvidenceRecordTimestampScopeFinder(evidenceRecord).findTimestampScope(timestampToken);
    }

    private void processExternalEvidenceRecord(EvidenceRecord externalEvidenceRecord) {
        // add reference to the covered evidence record
        addReference(externalEvidenceRecord.getTimestampedReferences(), getEvidenceRecordReference());
        // add references from covered evidence record
        addReferences(externalEvidenceRecord.getTimestampedReferences(), evidenceRecord.getTimestampedReferences());
        // add references from evidence record timestamps
        addReferences(externalEvidenceRecord.getTimestampedReferences(), getEncapsulatedReferencesFromTimestamps(getTimestamps()));
        // extract validation data
        populateSources(externalEvidenceRecord);
    }

    /**
     * Returns a list of TimestampedReferences for tokens encapsulated within the list of timestampTokens
     *
     * @param timestampTokens a list of {@link TimestampToken} to get references from
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getEncapsulatedReferencesFromTimestamps(List<TimestampToken> timestampTokens) {
        final List<TimestampedReference> references = new ArrayList<>();
        for (TimestampToken timestampToken : timestampTokens) {
            addReferences(references, getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
        }
        return references;
    }

    /**
     * Allows to populate all merged sources with extracted from a timestamp data
     *
     * @param timestampToken {@link TimestampToken} to populate data from
     */
    protected void populateSources(TimestampToken timestampToken) {
        if (timestampToken != null) {
            certificateSource.add(timestampToken.getCertificateSource());
            crlSource.add(timestampToken.getCRLSource());
            ocspSource.add(timestampToken.getOCSPSource());
        }
    }

    /**
     * Allows to populate all sources from an external evidence record
     *
     * @param externalEvidenceRecord {@link EvidenceRecord} to populate data from
     */
    protected void populateSources(EvidenceRecord externalEvidenceRecord) {
        if (externalEvidenceRecord != null) {
            // TODO : add extraction of embedded validation data
            for (TimestampToken timestampToken : externalEvidenceRecord.getTimestamps()) {
                populateSources(timestampToken);
            }
        }
    }

}
