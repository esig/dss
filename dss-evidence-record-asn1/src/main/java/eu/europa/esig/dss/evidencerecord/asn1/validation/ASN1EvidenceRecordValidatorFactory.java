package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidatorFactory;

/**
 * Loads the relevant validator for an ASN.1 Evidence Record document validation
 *
 */
public class ASN1EvidenceRecordValidatorFactory implements EvidenceRecordValidatorFactory {

    /**
     * Default constructor
     */
    public ASN1EvidenceRecordValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        ASN1EvidenceRecordValidator validator = new ASN1EvidenceRecordValidator();
        return validator.isSupported(document);
    }

    @Override
    public EvidenceRecordValidator create(DSSDocument document) {
        return new ASN1EvidenceRecordValidator(document);
    }

}
