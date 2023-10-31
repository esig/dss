package eu.europa.esig.dss.pki.jaxb;

import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.spi.DSSSecurityProvider;
import eu.europa.esig.dss.utils.Utils;

import java.io.File;
import java.security.Security;
import java.util.Collection;

public abstract class AbstractTestJaxbPKI {

    protected static JAXBCertEntityRepository repository = new JAXBCertEntityRepository();
    protected static final String XML_FOLDER = "src/test/resources/pki";

    static {
        Security.addProvider(DSSSecurityProvider.getSecurityProvider());
        loadPki();
    }

    private static void loadPki() {
        Collection<File> pkiFiles = Utils.listFiles(new File(XML_FOLDER), new String[]{"xml"}, false);
        for (File file : pkiFiles) {
            JAXBPKILoader builder = new JAXBPKILoader();
            builder.persistPKI(repository, file);
        }
    }

}
