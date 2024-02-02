package eu.europa.esig.dss.enumerations;

/**
 * Different types of Evidence Record time-stamps
 *
 */
public enum EvidenceRecordTimestampType {

    /* The initial archive time-stamp */
    ARCHIVE_TIMESTAMP,

    /* The time-stamp used to renew an previous archive time-stamp within the same ArchiveTimestampChain */
    TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP,

    /* The time-stamp used to renew a hash-tree, starting a new ArchiveTimeStampSequence */
    HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP

}
