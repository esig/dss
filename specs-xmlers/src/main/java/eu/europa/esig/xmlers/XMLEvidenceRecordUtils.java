package eu.europa.esig.xmlers;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.ers.xmlers.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Common XML Evidence Records schema utils
 *
 */
public final class XMLEvidenceRecordUtils extends XSDAbstractUtils {

    /** The Object Factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    /** The XMLERS XSD schema path */
    public static final String XML_ER = "/xsd/rfc6283_ers.xsd";

    /** Singleton */
    private static XMLEvidenceRecordUtils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Default constructor
     */
    private XMLEvidenceRecordUtils() {
        // empty
    }

    /**
     * Returns the instance of {@code XMLEvidenceRecordUtils}
     *
     * @return {@link XMLEvidenceRecordUtils}
     */
    public static XMLEvidenceRecordUtils getInstance() {
        if (singleton == null) {
            singleton = new XMLEvidenceRecordUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = new ArrayList<>();
        xsdSources.add(new StreamSource(XMLEvidenceRecordUtils.class.getResourceAsStream(XML_ER)));
        return xsdSources;
    }

}
