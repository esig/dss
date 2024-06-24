package eu.europa.esig.dss.spi.validation.analyzer.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

/**
 * This class performs processing of a timestamp
 *
 */
public interface TimestampAnalyzer {

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
