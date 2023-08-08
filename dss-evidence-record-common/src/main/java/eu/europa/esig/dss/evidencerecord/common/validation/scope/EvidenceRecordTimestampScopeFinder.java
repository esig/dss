package eu.europa.esig.dss.evidencerecord.common.validation.scope;

import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.scope.TimestampScopeFinder;

import java.util.List;

/**
 * Finds timestamped scopes for evidence record time-stamps
 *
 */
public class EvidenceRecordTimestampScopeFinder extends EvidenceRecordScopeFinder implements TimestampScopeFinder {

    /** The associated evidence record */
    private EvidenceRecord evidenceRecord;

    /**
     * Default constructor
     */
    public EvidenceRecordTimestampScopeFinder () {
        // empty
    }

    /**
     * Sets evidence record associated with the time-stamp
     *
     * @param evidenceRecord {@link EvidenceRecord}
     * @return this {@link EvidenceRecordTimestampScopeFinder}
     */
    public EvidenceRecordTimestampScopeFinder setEvidenceRecord(EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
        return this;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        return findEvidenceRecordScope(timestampToken.getReferenceValidations(), evidenceRecord.getDetachedContents());
    }

}
