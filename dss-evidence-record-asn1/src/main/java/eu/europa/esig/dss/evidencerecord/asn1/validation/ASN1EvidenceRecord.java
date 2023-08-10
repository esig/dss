package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.evidencerecord.asn1.validation.timestamp.ASN1EvidenceRecordTimestampSource;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecord;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordTimeStampSequenceVerifier;
import eu.europa.esig.dss.evidencerecord.common.validation.timestamp.EvidenceRecordTimestampSource;
import org.bouncycastle.asn1.tsp.EvidenceRecord;

/**
 * ASN.1 Evidence Record implementations (RFC 4998)
 *
 */
public class ASN1EvidenceRecord extends DefaultEvidenceRecord {

    /** The current EvidenceRecord object */
    private final EvidenceRecord evidenceRecord;

    /**
     * Default constructor to instantiate an ASN.1 Evidence Record
     *
     * @param evidenceRecord {@link EvidenceRecord} representing the evidence record document
     */
    public ASN1EvidenceRecord(EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    @Override
    public EvidenceRecordTypeEnum getReferenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

    @Override
    protected EvidenceRecordParser buildEvidenceRecordParser() {
        return new ASN1EvidenceRecordParser(evidenceRecord);
    }

    @Override
    protected EvidenceRecordTimeStampSequenceVerifier buildCryptographicEvidenceRecordVerifier() {
        return new ASN1EvidenceRecordTimeStampSequenceVerifier(this);
    }

    @Override
    protected EvidenceRecordTimestampSource<?> buildTimestampSource() {
        return new ASN1EvidenceRecordTimestampSource(this);
    }

}
