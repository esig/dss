package eu.europa.esig.dss.enumerations;

/**
 * Defines a type of data object associated with the ASiCManifest file
 *
 */
public enum ASiCManifestTypeEnum {

    /** The ASiCManifest is associated with a signature document */
    SIGNATURE,

    /** The ASiCManifest is associated with a time-stamp document */
    TIMESTAMP,

    /** The ASiCEvidenceRecordManifest is associated with an evidence record document */
    EVIDENCE_RECORD,

    /** The ASiCArchiveManifest is associated with an archival time-stamp document */
    ARCHIVE_MANIFEST

}
