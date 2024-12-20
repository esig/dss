package eu.europa.esig.dss.enumerations;

/**
 * Defines a version type of the ats-hash-index attribute from the archive-time-stamp-v3
 *
 */
public enum ArchiveTimestampHashIndexVersion {

    /**
     * Deprecated ats-hash-index Attribute.
     * See TS 101-733, ch. "6.4.2 ats-hash-index Attribute"
     */
    ATS_HASH_INDEX("ats-hash-index", "0.4.0.1733.2.5"),

    /**
     * Deprecated ats-hash-index-v2 Attribute.
     * See ETSI EN 319 122-1 v1.0.0, ch. "5.5.2 The ats-hash-index-v2 attribute"
     */
    ATS_HASH_INDEX_V2("ats-hash-index-v2", "0.4.0.19122.1.4"),

    /**
     * ats-hash-index-v3 Attribute.
     * See ETSI EN 319 122-1 v1.1.0, ch. "5.5.2 The ats-hash-index-v3 attribute"
     */
    ATS_HASH_INDEX_V3("ats-hash-index-v3", "0.4.0.19122.1.5");

    /** User-friendly label identifier */
    private final String label;

    /** OID */
    private final String oid;

    /**
     * Default constructor
     *
     * @param label {@link String} user-friendly identifier
     * @param oid {@link String} unique identifier
     */
    ArchiveTimestampHashIndexVersion(final String label, final String oid) {
        this.label = label;
        this.oid = oid;
    }

    /**
     * Gets a user-friendly {@code String} text label
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets unique object identifier
     *
     * @return {@link String}
     */
    public String getOid() {
        return oid;
    }

    /**
     * Gets the {@code ArchiveTimeStampHashIndexType} for the given label, if found
     *
     * @param label {@link String} user-friendly text label identifying the ats-hash-index version type
     * @return {@link ArchiveTimestampHashIndexVersion}
     */
    public static ArchiveTimestampHashIndexVersion forLabel(String label) {
        for (ArchiveTimestampHashIndexVersion version : values()) {
            if (version.getLabel().equals(label)) {
                return version;
            }
        }
        return null;
    }

    /**
     * Gets the {@code ArchiveTimeStampHashIndexType} for the given OID, if found
     *
     * @param oid {@link String} unique object identifier
     * @return {@link ArchiveTimestampHashIndexVersion}
     */
    public static ArchiveTimestampHashIndexVersion forOid(String oid) {
        for (ArchiveTimestampHashIndexVersion version : values()) {
            if (version.getOid().equals(oid)) {
                return version;
            }
        }
        return null;
    }

}
