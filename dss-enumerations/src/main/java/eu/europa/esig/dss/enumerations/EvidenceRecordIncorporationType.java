package eu.europa.esig.dss.enumerations;

/**
 * Defines an unsigned attribute type within a CAdES signature for incorporation of an evidence record
 * (i.e. internal vs external).
 *
 */
public enum EvidenceRecordIncorporationType {

    /**
     * Defines the internal-evidence-records attribute (clause 5.2) protecting the whole SignedData instance and
     * used in cases of attached signatures.
     */
    INTERNAL_EVIDENCE_RECORD,

    /**
     * Defines the external-evidence-records attribute (clause 5.3) also protecting the whole SignedData
     * instance not containing an eContent element within encapContentInfo (a detached signature), and the
     * external signed data.
     */
    EXTERNAL_EVIDENCE_RECORD

}
