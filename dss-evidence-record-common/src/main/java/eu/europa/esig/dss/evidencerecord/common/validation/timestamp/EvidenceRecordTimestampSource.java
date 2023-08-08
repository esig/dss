package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

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
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;

import java.util.ArrayList;
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
     * Creates and validates all timestamps
     * Must be called only once
     */
    protected void createAndValidate() {
        timestamps = new ArrayList<>();

        final List<TimestampedReference> signerDataReferences = getSignerDataReferences();
        List<TimestampedReference> previousTimestampReferences = new ArrayList<>();
        List<TimestampedReference> previousChainTimestampReferences = new ArrayList<>();

        List<TimestampedReference> references = new ArrayList<>();

        for (ArchiveTimeStampChainObject archiveTimeStampChain : evidenceRecord.getArchiveTimeStampSequence()) {

            addReferences(references, signerDataReferences);
            addReferences(references, previousChainTimestampReferences);
            previousChainTimestampReferences = new ArrayList<>();

            for (ArchiveTimeStampObject archiveTimeStamp : archiveTimeStampChain.getArchiveTimeStamps()) {

                addReferences(references, previousTimestampReferences);
                previousTimestampReferences = new ArrayList<>();

                TimestampToken timestampToken = createTimestampToken(archiveTimeStamp);
                timestampToken.getTimestampedReferences().addAll(references);
                timestampToken.setTimestampScopes(findTimestampScopes(timestampToken));

                // add time-stamp token
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
     * Returns a list of timestamped references for signed data objects
     *
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignerDataReferences() {
        return getSignerDataTimestampedReferences(evidenceRecord.getEvidenceRecordScopes());
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
        return new EvidenceRecordTimestampScopeFinder().setEvidenceRecord(evidenceRecord).findTimestampScope(timestampToken);
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

}
