package eu.europa.esig.dss.pki.business;


import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.service.Initializr;
import eu.europa.esig.dss.pki.service.PkiMarshallerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.*;
import java.util.stream.Stream;

/**
 * A class that performs post-construction initialization tasks for PKI resources.
 * It initializes the PKI resources by parsing XML files .
 */
public class PostConstructInitializr {

    private static final Logger LOG = LoggerFactory.getLogger(PostConstructInitializr.class);
    public static final String PATTERN = "glob:**/pki/*.xml";

    private static PostConstructInitializr instance = null;
    // The service for initializing the PKI resources.
    private static final Initializr initializrService = GenericFactory.getInstance().create(Initializr.class);

    // The service for marshalling PKI resources from XML files.
    private static PkiMarshallerService pkiMarshallerService;

    private static final String PATH = "src/main/resources/pki";

    private PostConstructInitializr() {
    }

    /**
     * Get the singleton instance of the PostConstructInitializr.
     *
     * @return The singleton instance of the PostConstructInitializr.
     */
    public static PostConstructInitializr getInstance() {
        if (instance == null) {
            synchronized (PostConstructInitializr.class) {
                pkiMarshallerService = GenericFactory.getInstance().create(PkiMarshallerService.class);
                instance = new PostConstructInitializr();
                init();
            }
        }
        return instance;
    }

    /**
     * Initializes the PKI resources by parsing the XML files located in resources directory.
     * This method is called during the post-construction phase.
     * It parses the XML files using the PkiMarshallerService and initializes the PKI resources using the Initializr service.
     */
    public static void init() {
        // Init certificate
        try {
            parsePKIResources();
            initializrService.init();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Parses the PKI resources by walking through the XML files .
     * It matches the XML files using a glob pattern and then calls the PkiMarshallerService to parse each file.
     * Any parsing error is logged as a RuntimeException.
     */
    protected static void parsePKIResources() throws URISyntaxException {
        ClassLoader classLoader = PostConstructInitializr.class.getClassLoader();
        URL resourceFolder = classLoader.getResource("pki");

        if (resourceFolder == null) {
            throw new RuntimeException("PKI resource folder not found.");
        }

        PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher(PATTERN);
        Path folderPath = Paths.get(resourceFolder.toURI());

        try (Stream<Path> pathStream = Files.walk(folderPath)) {
            pathStream
                    .filter(pathMatcher::matches)
                    .forEach(filePath -> {
                        LOG.info("Parsing file: {}", filePath.getFileName());
                        try (InputStream is = Files.newInputStream(filePath)) {
                            pkiMarshallerService.init(is, filePath.getFileName().toString());
                        } catch (IOException | JAXBException e) {
                            throw new RuntimeException(e);
                        }
                    });
        } catch (IOException e) {
            throw new RuntimeException("PKI parsing error", e);
        }
    }
}
