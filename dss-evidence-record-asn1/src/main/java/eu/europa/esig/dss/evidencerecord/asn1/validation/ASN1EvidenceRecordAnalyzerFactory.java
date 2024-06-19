package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.evidencerecord.common.validation.DefaultEvidenceRecordAnalyzer;
import eu.europa.esig.dss.spi.validation.analyzer.evidencerecord.EvidenceRecordAnalyzerFactory;

/**
 * Loads the relevant validator for an ASN.1 Evidence Record document validation
 *
 */
public class ASN1EvidenceRecordAnalyzerFactory implements EvidenceRecordAnalyzerFactory {

    /**
     * Default constructor
     */
    public ASN1EvidenceRecordAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        ASN1EvidenceRecordAnalyzer validator = new ASN1EvidenceRecordAnalyzer();
        return validator.isSupported(document);
    }

    @Override
    public DefaultEvidenceRecordAnalyzer create(DSSDocument document) {
        return new ASN1EvidenceRecordAnalyzer(document);
    }

}
