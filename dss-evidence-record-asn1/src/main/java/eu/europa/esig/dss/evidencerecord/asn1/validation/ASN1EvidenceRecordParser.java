package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.ArchiveTimeStampChainObject;
import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordParser;
import org.bouncycastle.asn1.tsp.EvidenceRecord;

import java.util.List;

/**
 * This class is used to parse an ASN.1 Evidence Record
 *
 */
public class ASN1EvidenceRecordParser implements EvidenceRecordParser {

    /** The BouncyCastle evidence record object to be parsed */
    private final EvidenceRecord evidenceRecord;

    /**
     * Default constructor
     *
     * @param evidenceRecord {@link EvidenceRecord}
     */
    public ASN1EvidenceRecordParser(final EvidenceRecord evidenceRecord) {
        this.evidenceRecord = evidenceRecord;
    }

    @Override
    public List<? extends ArchiveTimeStampChainObject> parse() {
        // TODO : to be implemented
        return null;
    }

}
