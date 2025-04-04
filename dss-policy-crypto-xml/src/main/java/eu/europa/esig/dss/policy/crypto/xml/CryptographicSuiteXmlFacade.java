package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;

/**
 * Performs marshalling/unmarshalling operation for the ETSI TS 119 312/322 XML schema
 *
 */
public class CryptographicSuiteXmlFacade extends AbstractJaxbFacade<SecuritySuitabilityPolicyType> {

    /** Location of the default cryptographic suite */
    private static final String DEFAULT_CRYPTOGRAPHIC_SUITES_LOCATION = "/suites/crypto-suites.xml";

    /**
     * Default constructor
     */
    protected CryptographicSuiteXmlFacade() {
        // empty
    }

    /**
     * Initializes a new {@code CryptographicSuitesFacade}
     *
     * @return {@link CryptographicSuiteXmlFacade}
     */
    public static CryptographicSuiteXmlFacade newFacade() {
        return new CryptographicSuiteXmlFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return CryptographicSuiteXmlUtils.getInstance().getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return CryptographicSuiteXmlUtils.getInstance().getSchema();
    }

    @Override
    protected JAXBElement<SecuritySuitabilityPolicyType> wrap(SecuritySuitabilityPolicyType jaxbObject) {
        return CryptographicSuiteXmlUtils.getInstance().OBJECT_FACTORY.createSecuritySuitabilityPolicy(jaxbObject);
    }

}
