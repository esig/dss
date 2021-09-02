package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.List;

/**
 * This interface is used to find a signature scope for a timestamp
 *
 */
public interface TimestampScopeFinder {

    /**
     * This method returns a timestamp scope for the given {@code TimestampToken}
     *
     * @param timestampToken {@link TimestampToken} to get signature scope for
     * @return a list of {@link SignatureScope}s
     */
    List<SignatureScope> findTimestampScope(TimestampToken timestampToken);

    /**
     * Sets the default DigestAlgorithm to use for {@code SignatureScope} digest computation
     *
     * @param digestAlgorithm {@link DigestAlgorithm} to use
     */
    void setDefaultDigestAlgorithm(DigestAlgorithm digestAlgorithm);

}
