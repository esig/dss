package eu.europa.esig.dss.evidencerecord.common.validation.scope;

import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.scope.EvidenceRecordScopeFinder;
import eu.europa.esig.dss.validation.scope.TimestampScopeFinder;

import java.util.Collections;
import java.util.List;

/**
 * Finds timestamped scopes for evidence record time-stamps
 *
 */
public class EvidenceRecordTimestampScopeFinder extends EvidenceRecordScopeFinder implements TimestampScopeFinder {

    /**
     * Default constructor
     */
    public EvidenceRecordTimestampScopeFinder(final EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return evidenceRecord.getEvidenceRecordScopes();
        }
        return Collections.emptyList();
    }

}
