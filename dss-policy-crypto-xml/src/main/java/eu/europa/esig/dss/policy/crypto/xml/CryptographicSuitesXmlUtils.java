package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ObjectFactory;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * ETSI TS 119 312/322 XML schema utils
 *
 */
public class CryptographicSuitesXmlUtils extends XSDAbstractUtils {

    /** The object factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    /** The Validation Policy XSD schema location */
    private static final String CRYPTO_SUITES_CATALOGUES_SCHEMA_LOCATION = "/xsd/rfc5698.xsd";

    /** The Validation Policy XSD schema location */
    private static final String CRYPTO_SUITES_ALGOCAT_SCHEMA_LOCATION = "/xsd/19322algocatxmlschema.xsd";

    /** Singleton */
    private static CryptographicSuitesXmlUtils singleton;

    /** Cached JAXBContext */
    private static JAXBContext jc;

    /**
     * Empty constructor
     */
    private CryptographicSuitesXmlUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CryptographicSuitesXmlUtils}
     *
     * @return {@link CryptographicSuitesXmlUtils}
     */
    public static CryptographicSuitesXmlUtils getInstance() {
        if (singleton == null) {
            singleton = new CryptographicSuitesXmlUtils();
        }
        return singleton;
    }

    /**
     * Gets the {@code JAXBContext}
     *
     * @return {@link JAXBContext}
     * @throws JAXBException if an exception occurs
     */
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.dss.policy.crypto.xml.jaxb.algocat.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(CryptographicSuitesXmlUtils.class.getResourceAsStream(CRYPTO_SUITES_CATALOGUES_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(CryptographicSuitesXmlUtils.class.getResourceAsStream(CRYPTO_SUITES_ALGOCAT_SCHEMA_LOCATION)));
        return xsdSources;
    }

}
