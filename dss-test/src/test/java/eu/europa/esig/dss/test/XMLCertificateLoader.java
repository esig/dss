package eu.europa.esig.dss.test;

import eu.europa.esig.dss.pki.config.JaxbConfig;
import eu.europa.esig.dss.pki.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.pki.service.PKICertificationEntityBuilder;
import eu.europa.esig.pki.manifest.Pki;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.Objects;

import static eu.europa.esig.dss.pki.constant.Constant.PATTERN;

public class XMLCertificateLoader {
    private static XMLCertificateLoader instance;
    PKICertificationEntityBuilder certificationEntityBuilder = PKICertificationEntityBuilder.getInstance();

    private XMLCertificateLoader() {

    }

    public static XMLCertificateLoader getInstance() {
        if (instance == null) {
            synchronized (XMLCertificateLoader.class) {
                instance = new XMLCertificateLoader();
            }
        }
        return instance;
    }

    public void loadCertificateFromXml(String certificationSubject) {
        ClassLoader classLoader = XMLCertificateLoader.class.getClassLoader();
        URL resourceFolder = classLoader.getResource("pki");

        if (resourceFolder == null) {
            throw new RuntimeException("PKI resource folder not found.");
        }

        File folder = new File(resourceFolder.getFile());

        if (isNotExist(certificationSubject, JaxbCertEntityRepository.getInstance())) {
            certificationEntityBuilder.persistCertEntity(getPki(folder, certificationSubject));
        }
    }


    public Pki getPki(File folder, String certificateSubject) {
        PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher(PATTERN);
        for (File file : Objects.requireNonNull(folder.listFiles())) {
            Path filePath = file.toPath();
            if (pathMatcher.matches(filePath) && processPKIFile(filePath, certificateSubject) != null) {
                return processPKIFile(filePath, certificateSubject);

            }
        }
        throw new RuntimeException("Xml not found.");
    }

    public Pki processPKIFile(Path filePath, String certificateSubject) {

        try (InputStream is = Files.newInputStream(filePath)) {
            Pki pki = loadPKI(is);

            if (isNotExist(pki, certificateSubject)) {
                return pki;
            }
        } catch (IOException | JAXBException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    private Pki loadPKI(InputStream inputStream) throws JAXBException, IOException {
        try (InputStream is = inputStream) {
            Unmarshaller unmarshaller = new JaxbConfig().getUnmarshaller();
            return (Pki) unmarshaller.unmarshal(new StreamSource(is));
        }
    }

    private boolean isNotExist(Pki pki, String certificationForLoad) {
        return pki.getCertificate().stream().anyMatch(certificateType -> certificationForLoad.equals(certificateType.getSubject()));
    }

    private boolean isNotExist(String id, CertEntityRepository certEntityRepository) {
        try {
            return Objects.isNull(certEntityRepository.getCertEntity(id));
        } catch (Error404Exception e) {
            return true;
        }
    }


}
