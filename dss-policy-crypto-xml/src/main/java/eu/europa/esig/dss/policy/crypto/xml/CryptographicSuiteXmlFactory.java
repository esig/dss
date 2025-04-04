package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;

/**
 * Implementation of a cryptographic suite using XML schema defined in ETSI TS 119 322.
 *
 */
public class CryptographicSuiteXmlFactory implements CryptographicSuiteFactory {

    /**
     * Default constructor
     */
    protected CryptographicSuiteXmlFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument cryptographicSuiteDocument) {
        return false;
    }

    @Override
    public CryptographicSuite loadDefaultCryptographicSuite() {
        return null;
    }

    @Override
    public CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument) {
        return null;
    }

}
