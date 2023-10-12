package eu.europa.esig.dss.evidencerecord.asn1.validation;

import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;

/**
 * Class for validation of an ASN.1 Evidence Record (RFC 4998)
 *
 */
public class ASN1EvidenceRecordValidator extends EvidenceRecordValidator {

    private static final Logger LOG = LoggerFactory.getLogger(ASN1EvidenceRecordValidator.class);

    /** The root element of the document to validate */
    private EvidenceRecord rootElement;

    /**
     * The default constructor for ASN1EvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(document);
        this.rootElement = toASN1Document(document).toASN1Structure();
    }

    private ERSEvidenceRecord toASN1Document(DSSDocument document) {
        try {
            return new ERSEvidenceRecord(document.openStream(), new JcaDigestCalculatorProviderBuilder().build());
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An ASN.1 file is expected : %s", e.getMessage()), e);
        }
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
    protected eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord buildEvidenceRecord() {
        // TODO : to be implemented
        return null;
    }

}
