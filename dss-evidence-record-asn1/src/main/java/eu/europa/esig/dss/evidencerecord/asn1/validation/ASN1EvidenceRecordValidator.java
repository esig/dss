package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;

/**
 * Class for validation of an ASN.1 Evidence Record (RFC 4998)
 *
 */
public class ASN1EvidenceRecordValidator extends EvidenceRecordValidator {

    /**
     * The default constructor for ASN1EvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(document);
    }

    /**
     * Empty constructor
     */
    ASN1EvidenceRecordValidator() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        byte firstByte = DSSUtils.readFirstByte(dssDocument);
        return DSSASN1Utils.isASN1SequenceTag(firstByte);
    }

    @Override
    protected EvidenceRecord buildEvidenceRecord() {
        // TODO : to be implemented
        return null;
    }

}
