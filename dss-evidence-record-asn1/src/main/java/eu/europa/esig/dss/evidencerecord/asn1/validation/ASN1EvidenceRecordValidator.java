package eu.europa.esig.dss.evidencerecord.asn1.validation;

import org.bouncycastle.asn1.tsp.EvidenceRecord;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;

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

    /** The root object of the document to validate */
    private EvidenceRecord evidenceRecordObject;

    /**
     * The default constructor for ASN1EvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(document);
        this.evidenceRecordObject = toASN1Document(document).toASN1Structure();
    }

	/**
     * Empty constructor
     */
    ASN1EvidenceRecordValidator() {
        // empty
    }
    
    private ERSEvidenceRecord toASN1Document(DSSDocument document) {
        try {
            return new ERSEvidenceRecord(document.openStream(), new JcaDigestCalculatorProviderBuilder().build());
        } catch (Exception e) {
            throw new IllegalInputException(String.format("An ASN.1 file is expected : %s", e.getMessage()), e);
        }
	}

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        byte firstByte = DSSUtils.readFirstByte(dssDocument);
        return DSSASN1Utils.isASN1SequenceTag(firstByte);
    }

    @Override
    protected eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord buildEvidenceRecord() {
        final ASN1EvidenceRecord evidenceRecord = new ASN1EvidenceRecord(this.evidenceRecordObject);
        evidenceRecord.setFilename(document.getName());
        evidenceRecord.setManifestFile(manifestFile);
        evidenceRecord.setDetachedContents(detachedContents);
        return evidenceRecord;
    }

}
