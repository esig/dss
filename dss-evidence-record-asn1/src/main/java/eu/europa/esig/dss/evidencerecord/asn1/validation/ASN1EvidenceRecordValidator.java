package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordValidator;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Class for validation of an ANS.1 Evidence Record (RFC 4998).
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public class ASN1EvidenceRecordValidator extends DefaultEvidenceRecordValidator {

    /**
     * Empty constructor
     */
    ASN1EvidenceRecordValidator() {
        super(new ASN1EvidenceRecordAnalyzer());
    }

    /**
     * The default constructor for XMLEvidenceRecordValidator.
     *
     * @param document The instance of {@code DSSDocument} to validate
     */
    public ASN1EvidenceRecordValidator(final DSSDocument document) {
        super(new ASN1EvidenceRecordAnalyzer(document));
    }

    @Override
    public ASN1EvidenceRecordAnalyzer getDocumentAnalyzer() {
        return (ASN1EvidenceRecordAnalyzer) super.getDocumentAnalyzer();
    }

}
