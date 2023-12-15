package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.spi.x509.tsp.TimestampIdentifierBuilder;

/**
 * Builds a unique identifier for a time-stamp encapsulated within a VRI dictionary
 *
 */
public class VriDictionaryTimestampIdentifierBuilder extends TimestampIdentifierBuilder {

    private static final long serialVersionUID = 1258485021800079377L;

    /** Number of the corresponding VRI dictionary in the PDF document */
    private final Integer dictionaryNumber;

    /**
     * Default constructor to build an identifier for a time-stamp extracted from a VRI dictionary
     *
     * @param timestampTokenBinaries byte array containing DER-encoded time-stamp
     * @param dictionaryNumber {@link Integer} number of the VRI dictionary
     */
    public VriDictionaryTimestampIdentifierBuilder(byte[] timestampTokenBinaries, Integer dictionaryNumber) {
        super(timestampTokenBinaries);
        this.dictionaryNumber = dictionaryNumber;
    }

    @Override
    protected Integer getTimestampPosition() {
        return dictionaryNumber;
    }

}
