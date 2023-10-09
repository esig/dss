package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.pki.jaxb.builder.JAXBCertEntityBuilder;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.spi.DSSSecurityProvider;

import java.io.File;
import java.net.URL;
import java.security.Security;
import java.util.Objects;

public abstract class AbstractTestJaxbPKI {

    protected static JAXBCertEntityRepository repository = new JAXBCertEntityRepository();
    protected static final String XML_FOLDER = "pki";

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
        loadPki();
    }

    private static void loadPki() {
        for (File file : Objects.requireNonNull(getFolder().listFiles())) {
            JAXBCertEntityBuilder builder = new JAXBCertEntityBuilder();
            builder.persistPKI(repository, file);
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
