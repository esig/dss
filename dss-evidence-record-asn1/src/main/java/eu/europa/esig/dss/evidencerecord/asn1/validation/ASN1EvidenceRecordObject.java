package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.evidencerecord.common.validation.EvidenceRecordObject;

/**
 * Represents an ASN1 Evidence Record object
 *
 */
public interface ASN1EvidenceRecordObject extends EvidenceRecordObject {

    /**
     * Gets Order attribute value of the corresponding element
     *
     * @return Order attribute value
     */
    int getOrder();

}
