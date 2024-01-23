package eu.europa.esig.dss.evidencerecord.asn1.validation.timestamp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.evidencerecord.asn1.validation.ASN1EvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

/**
 * This class is used to extract incorporated time-stamps from an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordTimestampSource extends EvidenceRecordTimestampSource<ASN1EvidenceRecord> {

    /**
     * Default constructor to instantiate a time-stamp source from an evidence record
     *
     * @param evidenceRecord {@link ASN1EvidenceRecord}
     */
    public ASN1EvidenceRecordTimestampSource(ASN1EvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp, EvidenceRecordTimestampType evidenceRecordTimestampType) {
        TimestampToken timestampToken = super.createTimestampToken(archiveTimeStamp, evidenceRecordTimestampType);
        timestampToken.setArchiveTimestampType(ArchiveTimestampType.ASN1_EVIDENCE_RECORD);
        return timestampToken;
    }

}
