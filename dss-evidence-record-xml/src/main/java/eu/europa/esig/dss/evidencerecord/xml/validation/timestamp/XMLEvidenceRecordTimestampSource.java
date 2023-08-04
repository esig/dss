package eu.europa.esig.dss.evidencerecord.xml.validation.timestamp;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampObject;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.xml.validation.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

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
    protected TimestampToken createTimestampToken(ArchiveTimeStampObject archiveTimeStamp) {
        TimestampToken timestampToken = super.createTimestampToken(archiveTimeStamp);
        timestampToken.setArchiveTimestampType(ArchiveTimestampType.XML_EVIDENCE_RECORD);
        return timestampToken;
    }

}
