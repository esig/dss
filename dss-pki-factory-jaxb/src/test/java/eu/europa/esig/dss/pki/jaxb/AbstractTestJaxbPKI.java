package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.pki.jaxb.builder.JAXBCertEntityBuilder;
import eu.europa.esig.dss.pki.jaxb.repository.JaxbCertEntityRepository;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.security.Security;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractTestJaxbPKI {

    protected static JaxbCertEntityRepository repository = new JaxbCertEntityRepository();
    protected static final String XML_FOLDER = "pki";

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
        loadPki();
    }

    private static void loadPki() {
        for (File file : Objects.requireNonNull(getFolder().listFiles())) {
            JAXBCertEntityBuilder builder = new JAXBCertEntityBuilder();
            try (InputStream is = Files.newInputStream(file.toPath())) {
                XmlPki pki = loadPKI(is);
                builder.persistPKI(repository, pki);
            } catch (Exception e) {
                fail(e);
            }

        }
    }

    private static XmlPki loadPKI(InputStream inputStream) throws JAXBException, IOException, SAXException {
        try (InputStream is = inputStream) {
            Unmarshaller unmarshaller = PKIJaxbFacade.newFacade().getUnmarshaller(true);
            JAXBElement<XmlPki> unmarshalled = (JAXBElement<XmlPki>) unmarshaller.unmarshal(is);
            return unmarshalled.getValue();
        }
    }

    private static File getFolder() {
        URL resourceFolder = AbstractTestJaxbPKI.class.getClassLoader().getResource(XML_FOLDER);
        if (resourceFolder == null) {
            throw new RuntimeException("PKI resource folder not found.");
        }
        return new File(resourceFolder.getFile());
    }

}
