package eu.europa.esig.dss.pki.jaxb.config;


import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;


/**
 * A utility class that provides configuration for JAXB .
 * It allows the creation of an Unmarshaller for unmarshalling XML data into Java objects.
 */
public class JaxbConfig {

    /**
     * Creates and returns a new Unmarshaller for unmarshalling XML data into Java objects.
     *
     * @return An Unmarshaller instance for unmarshalling XML data.
     * @throws JAXBException If an error occurs during the creation of the Unmarshaller.
     */
    public Unmarshaller getUnmarshaller() throws JAXBException {
        // Create a JAXBContext for the specified class.
        JAXBContext jaxbContext = PKIFactoryJaxbUtils.getInstance().getJAXBContext();

        // Create and return an Unmarshaller instance from the JAXBContext.
        return jaxbContext.createUnmarshaller();
    }
}
