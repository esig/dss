package eu.europa.esig.xmlers;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.ers.xmlers.jaxb.EvidenceRecordType;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

/**
 * Performs marshalling/unmarshalling operation for a XML Evidence Records XML
 *
 */
public class XMLEvidenceRecordFacade extends AbstractJaxbFacade<EvidenceRecordType> {

    /** XMLER utils */
    private static final XMLEvidenceRecordUtils XMLER_UTILS = XMLEvidenceRecordUtils.getInstance();

    /**
     * Creates a new facade
     *
     * @return {@link XMLEvidenceRecordFacade}
     */
    public static XMLEvidenceRecordFacade newFacade() {
        return new XMLEvidenceRecordFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return XMLER_UTILS.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return XMLER_UTILS.getSchema();
    }

    @Override
    protected JAXBElement<EvidenceRecordType> wrap(EvidenceRecordType jaxbObject) {
        return XMLEvidenceRecordUtils.OBJECT_FACTORY.createEvidenceRecord(jaxbObject);
    }

}
