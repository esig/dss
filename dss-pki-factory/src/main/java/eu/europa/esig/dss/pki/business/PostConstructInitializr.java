package eu.europa.esig.dss.pki.business;


import eu.europa.esig.dss.pki.factory.GenericFactory;
import eu.europa.esig.dss.pki.service.Initializr;
import eu.europa.esig.dss.pki.service.PkiMarshallerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * A class that performs post-construction initialization tasks for PKI resources.
 * It initializes the PKI resources by parsing XML files .
 */
public class PostConstructInitializr {

    private static final Logger LOG = LoggerFactory.getLogger(PostConstructInitializr.class);

    private static PostConstructInitializr instance = null;
    // The service for initializing the PKI resources.
    private static final Initializr initializrService = GenericFactory.getInstance().create(Initializr.class);

    // The service for marshalling PKI resources from XML files.
    private final static PkiMarshallerService pkiMarshallerService = GenericFactory.getInstance().create(PkiMarshallerService.class);

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
        parsePKIResources();
        // Init certificate
        try {
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
    protected static void parsePKIResources() {
        try {
            PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher("glob:**/pki/*.xml");

            Files.walkFileTree(Paths.get(PATH), new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    if (pathMatcher.matches(file)) {
                        LOG.info("Parsing file: {}", file.getFileName());
                        try (InputStream is = Files.newInputStream(file)) {
                            try {
                                pkiMarshallerService.init(is, file.getFileName().toString());
                            } catch (JAXBException e) {
                                throw new RuntimeException(e);
                            }
                        }
                    }
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            throw new RuntimeException("PKI parsing error", e);
        }
    }
}
