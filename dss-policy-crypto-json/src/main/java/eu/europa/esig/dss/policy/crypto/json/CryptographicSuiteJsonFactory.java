package eu.europa.esig.dss.policy.crypto.json;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.json.JSONParser;
import eu.europa.esig.json.JsonObjectWrapper;

import java.io.InputStream;
import java.util.List;

/**
 * Implementation of a cryptographic suite using JSON schema defined in ETSI TS 119 322.
 *
 */
public class CryptographicSuiteJsonFactory implements CryptographicSuiteFactory {

    /** Location of the default cryptographic suite */
    private static final String DEFAULT_CRYPTOGRAPHIC_SUITES_LOCATION = "/suite/dss-crypto-suite.json";

    /**
     * Default constructor
     */
    public CryptographicSuiteJsonFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument cryptographicSuiteDocument) {
        try (InputStream is = cryptographicSuiteDocument.openStream()) {
            List<String> errors = CryptographicSuiteJsonUtils.getInstance().validateAgainstSchema(is);
            return errors == null || errors.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public CryptographicSuite loadDefaultCryptographicSuite() {
        return loadCryptographicSuite(CryptographicSuiteJsonFactory.class.getResourceAsStream(DEFAULT_CRYPTOGRAPHIC_SUITES_LOCATION));
    }

    @Override
    public CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument) {
        return loadCryptographicSuite(cryptographicSuiteDocument.openStream());
    }

    @Override
    public CryptographicSuite loadCryptographicSuite(InputStream cryptographicSuiteInputStream) {
        try (InputStream is = cryptographicSuiteInputStream) {
            JsonObjectWrapper json = new JSONParser().parse(is);
            JsonObjectWrapper securitySuitabilityPolicyType = json.getAsObject(CryptographicSuiteJsonConstraints.SECURITY_SUITABILITY_POLICY);
            if (securitySuitabilityPolicyType == null) {
                throw new IllegalArgumentException(String.format("The root element of JSON shall be a JSON object of '%s' type!",
                        CryptographicSuiteJsonConstraints.SECURITY_SUITABILITY_POLICY));
            }
            return new CryptographicSuiteJsonWrapper(securitySuitabilityPolicyType);
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

}
