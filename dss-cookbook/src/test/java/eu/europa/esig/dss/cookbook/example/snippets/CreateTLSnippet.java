package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.trustedlist.TrustedListFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CreateTLSnippet {

    /** The objet factory to use */
    private final ObjectFactory objectFactory = new ObjectFactory();

    @Test
    void createTrustedList() throws Exception {
        // tag::demoSign[]
        // Create an empty 'TrustServiceStatusList' element
        TrustStatusListType trustStatusListType = objectFactory.createTrustStatusListType();

        // Fill the requred information, Id, ...
        trustStatusListType.setId("Demo-TL");

        // Store to file
        DSSDocument modifiedUnsignedTL = null;
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(trustStatusListType, baos, false);
            modifiedUnsignedTL = new InMemoryDocument(baos.toByteArray());
        }
        modifiedUnsignedTL.save("target/unsigned_TL.xml");
        // end::demoSign[]

        assertTrue(new File("target/unsigned_TL.xml").delete());
    }

    @Test
    void editValidTrustedList() throws Exception {
        // tag::demoEdit[]
        // Load original Trusted List
        final File file = new File("src/main/resources/trusted-list.xml");

        // Parse it to JAXB object
        final TrustStatusListType jaxbObject = TrustedListFacade.newFacade().unmarshall(file, false);
        assertNotNull(jaxbObject);

        // Modify JAXB Object where required
        jaxbObject.getSchemeInformation().setTSLSequenceNumber(new BigInteger("39"));

        // Store to file
        DSSDocument modifiedUnsignedTL;
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            TrustedListFacade.newFacade().marshall(jaxbObject, baos, false);
            modifiedUnsignedTL = new InMemoryDocument(baos.toByteArray());
        }
        modifiedUnsignedTL.save("target/unsigned_TL.xml");
        // end::demoEdit[]

        assertTrue(new File("target/unsigned_TL.xml").delete());
    }

}
