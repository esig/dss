package eu.europa.esig.dss.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.DocumentValidator;

/**
 * The interface to be used for evidence record validation
 *
 */
public interface EvidenceRecordValidator extends DocumentValidator {

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
