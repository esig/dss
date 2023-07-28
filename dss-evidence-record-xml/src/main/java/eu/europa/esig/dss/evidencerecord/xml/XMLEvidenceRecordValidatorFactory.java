package eu.europa.esig.dss.evidencerecord.xml;


import eu.europa.esig.dss.evidencerecord.common.EvidenceRecordValidator;
import eu.europa.esig.dss.evidencerecord.common.EvidenceRecordValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * Loads the relevant validator for an XML Evidence Record document validation
 */
public class XMLEvidenceRecordValidatorFactory implements EvidenceRecordValidatorFactory {

    /**
     * Default constructor
     */
    public XMLEvidenceRecordValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        XMLEvidenceRecordValidator validator = new XMLEvidenceRecordValidator();
        return validator.isSupported(document);
    }

    @Override
    public EvidenceRecordValidator create(DSSDocument document) {
        return new XMLEvidenceRecordValidator(document);
    }

}
