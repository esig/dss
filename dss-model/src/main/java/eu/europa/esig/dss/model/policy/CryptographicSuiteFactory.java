package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.model.DSSDocument;

/**
 * Interface containing methods to load a {@code eu.europa.esig.dss.model.policy.CryptographicSuite} object
 *
 */
public interface CryptographicSuiteFactory {

    /**
     * Evaluates whether the cryptographic suite {@code DSSDocument} is supported by the current implementation
     *
     * @param cryptographicSuiteDocument {@link DSSDocument} containing cryptographic suite
     * @return TRUE if the document is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument cryptographicSuiteDocument);

    /**
     * Loads a default cryptographic suite provided by the application
     *
     * @return {@link CryptographicSuite}
     */
    CryptographicSuite loadDefaultCryptographicSuite();

    /**
     * Loads a cryptographic suite from a {@code DSSDocument} provided to the method
     *
     * @param cryptographicSuiteDocument {@link DSSDocument}
     * @return {@link CryptographicSuite}
     */
    CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument);

}
