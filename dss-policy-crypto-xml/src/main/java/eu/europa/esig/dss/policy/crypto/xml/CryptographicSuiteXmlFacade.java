package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Performs marshalling/unmarshalling operation for the ETSI TS 119 312/322 XML schema
 *
 */
public class CryptographicSuiteXmlFacade extends AbstractJaxbFacade<SecuritySuitabilityPolicyType> {

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

    /**
     * Gets the cryptographic suite from the {@code InputStream}
     *
     * @param is {@link InputStream}
     * @return {@link CryptographicSuite}
     * @throws JAXBException if {@link JAXBException} occurs
     * @throws XMLStreamException if {@link XMLStreamException} occurs
     * @throws IOException if {@link IOException} occurs
     * @throws SAXException if {@link SAXException} occurs
     */
    public CryptographicSuite getCryptographicSuite(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
        Objects.requireNonNull(is, "The provided cryptographic suite is null");
        return new CryptographicSuiteXmlWrapper(unmarshall(is));
    }

}
