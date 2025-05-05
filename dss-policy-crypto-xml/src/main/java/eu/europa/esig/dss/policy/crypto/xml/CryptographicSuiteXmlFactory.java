package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Implementation of a cryptographic suite using XML schema defined in ETSI TS 119 322.
 *
 */
public class CryptographicSuiteXmlFactory implements CryptographicSuiteFactory {

    /** Location of the default cryptographic suite */
    private static final String DEFAULT_CRYPTOGRAPHIC_SUITES_LOCATION = "/suite/dss-crypto-suite.xml";

    /**
     * Default constructor
     */
    public CryptographicSuiteXmlFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument cryptographicSuiteDocument) {
        try (InputStream is = cryptographicSuiteDocument.openStream()) {
            SecuritySuitabilityPolicyType suitabilityPolicyType = CryptographicSuiteXmlFacade.newFacade().unmarshall(is, false);
            return suitabilityPolicyType != null;
        } catch (IOException | JAXBException | XMLStreamException | SAXException e) {
            return false;
        }
    }

    @Override
    public CryptographicSuite loadDefaultCryptographicSuite() {
        return loadCryptographicSuite(CryptographicSuiteXmlFactory.class.getResourceAsStream(DEFAULT_CRYPTOGRAPHIC_SUITES_LOCATION));
    }

    @Override
    public CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument) {
        return loadCryptographicSuite(cryptographicSuiteDocument.openStream());
    }

    @Override
    public CryptographicSuite loadCryptographicSuite(InputStream cryptographicSuiteInputStream) {
        try (InputStream is = cryptographicSuiteInputStream) {
            return CryptographicSuiteXmlFacade.newFacade().getCryptographicSuite(is);
        } catch (Exception e) {
            throw new UnsupportedOperationException(
                    String.format("Unable to load the default policy document. Reason : %s", e.getMessage()), e);
        }
    }

}
