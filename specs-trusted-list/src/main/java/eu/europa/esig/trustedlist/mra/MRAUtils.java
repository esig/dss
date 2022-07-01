package eu.europa.esig.trustedlist.mra;

import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import eu.europa.esig.xmldsig.XSDAbstractUtils;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * MRA Utils
 *
 */
public class MRAUtils extends XSDAbstractUtils {

    /** The Object Factory to use */
    public static final ObjectFactory OBJECT_FACTORY = TrustedListUtils.OBJECT_FACTORY;

    /** The MRA XSD schema location */
    public static final String MRA_SCHEMA_LOCATION = "/xsd/mra/mra_element.xsd";

    /** Singleton */
    private static MRAUtils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private MRAUtils() {
    }

    /**
     * Returns instance of {@code MRAUtils}
     *
     * @return {@link MRAUtils}
     */
    public static MRAUtils getInstance() {
        if (singleton == null) {
            singleton = new MRAUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
                    eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class,
                    eu.europa.esig.trustedlist.jaxb.tslx.ObjectFactory.class,
                    eu.europa.esig.trustedlist.jaxb.ecc.ObjectFactory.class,
                    eu.europa.esig.trustedlist.jaxb.mra.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = TrustedListUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(MRA_SCHEMA_LOCATION)));
        return xsdSources;
    }

}