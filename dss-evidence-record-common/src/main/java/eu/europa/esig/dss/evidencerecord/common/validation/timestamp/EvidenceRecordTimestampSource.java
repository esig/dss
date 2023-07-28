package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecord;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampMessageDigestBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class is used for extraction and validation of time-stamps incorporated within an Evidence Record
 *
 */
public abstract class EvidenceRecordTimestampSource<ER extends EvidenceRecord> extends AbstractTimestampSource {

    private static final Logger LOG = LoggerFactory.getLogger(EvidenceRecordTimestampSource.class);

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
        final List<TimestampedReference> references = new ArrayList<>();

        for (ArchiveTimeStampChainObject archiveTimeStampChain : evidenceRecord.getArchiveTimeStampSequence()) {
            for (ArchiveTimeStampObject archiveTimeStamp : archiveTimeStampChain.getArchiveTimeStamps()) {

                // TODO : populate references
                TimestampToken timestampToken = createTimestampToken(archiveTimeStamp, references);

                DSSMessageDigest messageDigest = getTimestampMessageImprintDigestBuilder(archiveTimeStamp).getArchiveTimestampMessageDigest();
                timestampToken.matchData(messageDigest);

                // add time-stamp token
                timestamps.add(timestampToken);
            }
        }
    }

    /**
     * Returns a related {@link TimestampMessageDigestBuilder}
     *
     * @param archiveTimeStampObject {@link ArchiveTimeStampObject} containing a time-stamp to get message-imprint digest builder for
     * @return {@link TimestampMessageDigestBuilder}
     */
    protected abstract EvidenceRecordTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(ArchiveTimeStampObject archiveTimeStampObject);

    /**
     * Creates a time-stamp token
     *
     * @param archiveTimeStamp {@link ArchiveTimeStampObject} containing time-stamp's token data
     * @param references a list of {@link TimestampedReference}s
     * @return {@link TimestampToken}
     */
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp, List<TimestampedReference> references) {
        try {
            return new TimestampToken(
                    archiveTimeStamp.getTimestampToken(), TimestampType.EVIDENCE_RECORD_TIMESTAMP, references);
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.warn("Unable to build timestamp token from binaries '{}'! Reason : {}",
                        Utils.toBase64(archiveTimeStamp.getTimestampToken()), e.getMessage(), e);
            } else {
                LOG.warn("Unable to build timestamp token! Reason : {}", e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     * Returns a list of timestamped references for signed data objects
     *
     * @return a list of {@link TimestampedReference}s
     */
    protected List<TimestampedReference> getSignerDataReferences() {
        // TODO : to be implemented
        return Collections.emptyList();
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
