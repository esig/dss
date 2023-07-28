package eu.europa.esig.dss.evidencerecord.xml.validation.timestamp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampMessageDigestBuilder;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import java.util.List;

/**
 * This class is used to extract incorporated time-stamps from an XML Evidence Record
 *
 */
public class XMLEvidenceRecordTimestampSource extends EvidenceRecordTimestampSource<XmlEvidenceRecord> {

    /**
     * Default constructor to instantiate a time-stamp source from an evidence record
     *
     * @param evidenceRecord {@link XmlEvidenceRecord}
     */
    public XMLEvidenceRecordTimestampSource(XmlEvidenceRecord evidenceRecord) {
        super(evidenceRecord);
    }

    @Override
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp, List<TimestampedReference> references) {
        TimestampToken timestampToken = super.createTimestampToken(archiveTimeStamp, references);
        timestampToken.setArchiveTimestampType(ArchiveTimestampType.XML_EVIDENCE_RECORD);
        return timestampToken;
    }

    @Override
    protected EvidenceRecordTimestampMessageDigestBuilder getTimestampMessageImprintDigestBuilder(ArchiveTimeStampObject archiveTimeStampObject) {
        return new XMLEvidenceRecordTimestampMessageDigestBuilder(evidenceRecord, archiveTimeStampObject);
    }

}
