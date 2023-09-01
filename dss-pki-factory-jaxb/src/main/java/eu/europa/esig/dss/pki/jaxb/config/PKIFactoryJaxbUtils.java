package eu.europa.esig.dss.pki.jaxb.config;

import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * Contains utils for dealing with PKI Manifest
 */
public final class PKIFactoryJaxbUtils extends XSDAbstractUtils {

    /**
     * The PKI Manifest XSD schema path
     */
    public static final String PKI_MANIFEST = "/xsd/pki.xsd";

    /**
     * Singleton
     */
    private static PKIFactoryJaxbUtils singleton;

    /**
     * JAXBContext
     */
    private JAXBContext jc;

    private PKIFactoryJaxbUtils() {
        // empty
    }

    /**
     * Returns the instance of {@code ASiCManifestUtils}
     *
     * @return {@link PKIFactoryJaxbUtils}
     */
    public static PKIFactoryJaxbUtils getInstance() {
        if (singleton == null) {
            singleton = new PKIFactoryJaxbUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.dss.pki.jaxb.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(PKIFactoryJaxbUtils.class.getResourceAsStream(PKI_MANIFEST)));
        return xsdSources;
    }

}
