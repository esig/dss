package eu.europa.esig.dss.evidencerecord.common.validation.timestamp;

import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;

/**
 * Builds an identifier for a time-stamp encapsulated within an evidence record
 *
 */
public class EvidenceRecordTimestampIdentifierBuilder extends TimestampIdentifierBuilder {

    private static final long serialVersionUID = -4742875671551626836L;

    /** Prefix string for the order of archive time-stamp chain element */
    private static final String ARCHIVE_TIMESTAMP_CHAIN_ORDER_PREFIX = "-ATC-";

    /** Prefix string for order of archive time-stamp element */
    private static final String ARCHIVE_TIMESTAMP_ORDER_PREFIX = "-AT-";

    /** Position of the time-stamp token's corresponding archive time-stamp chain within an evidence record */
    private Integer archiveTimeStampChainOrder;

    /** Position of the time-stamp token within its archive time-stamp chain */
    private Integer archiveTimeStampOrder;

    /**
     * Default constructor to build an identifier for an evidence record time-stamp
     *
     * @param timestampTokenBinaries time-stamp token DER-encoded binaries
     */
    public EvidenceRecordTimestampIdentifierBuilder(final byte[] timestampTokenBinaries) {
        super(timestampTokenBinaries);
    }

    /**
     * Sets position of the archive time-stamp chain within an evidence record
     *
     * @param archiveTimeStampChainOrder position number
     * @return this {@link EvidenceRecordTimestampIdentifierBuilder}
     */
    public EvidenceRecordTimestampIdentifierBuilder setArchiveTimeStampChainOrder(Integer archiveTimeStampChainOrder) {
        this.archiveTimeStampChainOrder = archiveTimeStampChainOrder;
        return this;
    }

    /**
     * Sets position of the archive time-stamp within the archive time-stamp chain element
     *
     * @param archiveTimeStampOrder position number
     * @return this {@link EvidenceRecordTimestampIdentifierBuilder}
     */
    public EvidenceRecordTimestampIdentifierBuilder setArchiveTimeStampOrder(Integer archiveTimeStampOrder) {
        this.archiveTimeStampOrder = archiveTimeStampOrder;
        return this;
    }

    @Override
    public EvidenceRecordTimestampIdentifierBuilder setFilename(String filename) {
        return (EvidenceRecordTimestampIdentifierBuilder) super.setFilename(filename);
    }

    @Override
    protected String getTimestampPosition() {
        StringBuilder sb = new StringBuilder();
        if (archiveTimeStampChainOrder != null) {
            sb.append(ARCHIVE_TIMESTAMP_CHAIN_ORDER_PREFIX);
            sb.append(archiveTimeStampChainOrder);
        }
        if (archiveTimeStampOrder != null) {
            sb.append(ARCHIVE_TIMESTAMP_ORDER_PREFIX);
            sb.append(archiveTimeStampOrder);
        }
        return sb.toString();
    }

}
