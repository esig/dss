package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;

import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * POE provided by an evidence record
 *
 */
public class EvidenceRecordPOE extends POE {

    /** The evidence record */
    private final EvidenceRecordWrapper evidenceRecord;

    /**
     * The constructor to instantiate POE by an evidence record
     *
     * @param evidenceRecord {@link EvidenceRecordWrapper}
     */
    public EvidenceRecordPOE(EvidenceRecordWrapper evidenceRecord) {
        super(getPOETime(evidenceRecord));
        this.evidenceRecord = evidenceRecord;
    }

    private static Date getPOETime(EvidenceRecordWrapper evidenceRecord) {
        Objects.requireNonNull(evidenceRecord, "The evidenceRecord must be defined!");
        Objects.requireNonNull(evidenceRecord.getFirstTimestamp(), "EvidenceRecord shall have at leats one time-stamp!");
        return evidenceRecord.getFirstTimestamp().getProductionTime();
    }

    @Override
    public String getPOEProviderId() {
        return evidenceRecord.getId();
    }

    @Override
    public List<XmlTimestampedObject> getPOEObjects() {
        return evidenceRecord.getCoveredObjects();
    }

    @Override
    public boolean isTokenProvided() {
        return true;
    }

}
