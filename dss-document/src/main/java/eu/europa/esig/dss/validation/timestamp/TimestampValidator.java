package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * The interface to be used for timestamp validation
 */
public interface TimestampValidator {

    /**
     * Returns a single TimestampToken to be validated
     *
     * @return {@link TimestampToken}
     */
    TimestampToken getTimestamp();

    /**
     * Returns the timestamped data
     *
     * @return {@link DSSDocument} timestamped data
     */
    DSSDocument getTimestampedData();

}
