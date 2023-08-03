package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.timestamp.TimestampToken;

import java.util.List;

/**
 * Representation of an Evidence Record
 *
 */
public interface EvidenceRecord {

    /**
     * Returns a list of archive data object validations
     *
     * @return a list of {@link ReferenceValidation} objects corresponding to each archive data object validation
     */
    List<ReferenceValidation> getReferenceValidation();

    /**
     * Returns a list of incorporated timestamp tokens
     *
     * @return a list of {@link TimestampToken}s
     */
    List<TimestampToken> getTimestamps();

}
