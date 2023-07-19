package eu.europa.esig.dss.pki.business;


import eu.europa.esig.dss.pki.service.Initializr;
import eu.europa.esig.dss.pki.service.PkiMarshallerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.JAXBException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;


public class PostConstructInitializr {

    private static final Logger LOG = LoggerFactory.getLogger(PostConstructInitializr.class);

    //    @Autowired
    private Initializr initializrService = Initializr.getInstance();

    //   @Autowired
    private PkiMarshallerService pkiMarshallerService = PkiMarshallerService.getInstance();


    //    @PostConstruct
    public void init() {


        this.parsePKIResources();

        // Init certificate
        try {
            initializrService.init();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void parsePKIResources() {
        try {
            PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher("glob:**/pki/*.xml");

            Files.walkFileTree(Paths.get("src/main/resources/pki"), new SimpleFileVisitor<Path>() {
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
