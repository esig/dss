package eu.europa.esig.trustedlist.mra;

import eu.europa.esig.trustedlist.TrustedListFacade;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

/**
 * Performs marshalling/unmarshalling operation for a TrustedList XML with applied MRA scheme
 *
 */
public class MRAFacade extends TrustedListFacade {

    /** MRA utils */
    private static final MRAUtils MRA_UTILS = MRAUtils.getInstance();

    /**
     * Creates a new facade
     *
     * @return {@link MRAFacade}
     */
    public static MRAFacade newFacade() {
        return new MRAFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return MRA_UTILS.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return MRA_UTILS.getSchema();
    }

}
