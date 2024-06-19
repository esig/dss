package eu.europa.esig.dss.spi.validation.analyzer.evidencerecord;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.spi.validation.analyzer.DocumentAnalyzer;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;

/**
 * Interface to perform validation of an evidence record document
 *
 */
public interface EvidenceRecordAnalyzer extends DocumentAnalyzer {

    /**
     * Returns a single EvidenceRecord to be validated
     *
     * @return {@link EvidenceRecord}
     */
    EvidenceRecord getEvidenceRecord();

    /**
     * This method returns a type of the evidence record supported by the current validator
     *
     * @return {@link EvidenceRecordTypeEnum}
     */
    EvidenceRecordTypeEnum getEvidenceRecordType();

}
