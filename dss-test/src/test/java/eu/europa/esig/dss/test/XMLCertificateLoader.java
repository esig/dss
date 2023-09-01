package eu.europa.esig.dss.test;

import eu.europa.esig.dss.pki.jaxb.XmlPki;
import eu.europa.esig.dss.pki.jaxb.config.PKIJaxbFacade;
import eu.europa.esig.dss.pki.jaxb.db.JaxbCertEntityRepository;
import eu.europa.esig.dss.pki.jaxb.service.PKICertificationEntityBuilder;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.repository.CertEntityRepository;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static eu.europa.esig.dss.pki.jaxb.constant.PKIJaxbConstant.XML_FOLDER;

public class XMLCertificateLoader {

    // TODO : not singleton
    private static final Logger LOG = LoggerFactory.getLogger(XMLCertificateLoader.class);

    private final PKICertificationEntityBuilder certificationEntityBuilder = new PKICertificationEntityBuilder();

    public XMLCertificateLoader(CertEntityRepository<? extends CertEntity> repository) {
        this.repository = repository;
    }

    private CertEntityRepository<? extends CertEntity> repository;
    private final Set<Path> createdPKIs = new HashSet<>();
    private final Map<Path, XmlPki> filePkiMap = new HashMap<>();

    // TODO : instantiate with JaxbCertEntityRepository

   private CertificateSource certificateSource;

    public void setCommonTrustedCertificateSource(CertificateSource certificateSource) {
        this.certificateSource = certificateSource;
    }

    private void synchronizeCertificateSource() {
        if (certificateSource == null) {
            LOG.warn("No CommonTrustedCertificateSource to be synchronized");
            return;
        }
        repository.getTrustAnchors().stream().map(CertEntity::getCertificateToken)
                .forEach(certificateToken -> certificateSource.addCertificate(certificateToken));
    }

    // return CertEntity
    public CertEntity loadCertificateEntityFromXml(String certificateSubjectName) {
        ClassLoader classLoader = XMLCertificateLoader.class.getClassLoader();
        URL resourceFolder = classLoader.getResource(XML_FOLDER);
        if (resourceFolder == null) {
            throw new RuntimeException("PKI resource folder not found.");
        }
        File folder = new File(resourceFolder.getFile());
        CertEntity dbCertEntity = repository.getCertEntityBySubject(certificateSubjectName);
        if (dbCertEntity == null) {
            certificationEntityBuilder.persistPKI(repository, getPki(folder, certificateSubjectName));
            // TODO : synchronize TrustedCertSource
            dbCertEntity = repository.getCertEntityBySubject(certificateSubjectName);
            synchronizeCertificateSource();
        }
        if (dbCertEntity == null) {
            throw new RuntimeException("CertEntity not found");
        }
        return dbCertEntity;

    }


    public XmlPki getPki(File folder, String certificateSubject) {
        for (File file : Objects.requireNonNull(folder.listFiles())) {

            Path filePath = file.toPath();
            // if createdPKIs.contains FILE - continue
            if (createdPKIs.contains(filePath)) {
                continue;
            }

            XmlPki pki = processPKIFile(filePath, certificateSubject);

            if (pki != null) {
                createdPKIs.add(filePath);
                return pki;
            }
        }
        throw new RuntimeException("Xml not found.");
    }

    public XmlPki processPKIFile(Path filePath, String certificateSubject) {
        XmlPki pki = filePkiMap.get(filePath);
        // map.get filePath
        if (pki == null) {
            try (InputStream is = Files.newInputStream(filePath)) {
                pki = loadPKI(is);
                filePkiMap.put(filePath, pki);
            } catch (IOException | JAXBException | SAXException e) {
                throw new RuntimeException(e);
            }
        }

        if (checkPKIContainsCertificate(pki, certificateSubject)) {
            return pki;
        }
        return null;
    }

    private XmlPki loadPKI(InputStream inputStream) throws JAXBException, IOException, SAXException {
        try (InputStream is = inputStream) {
            Unmarshaller unmarshaller = PKIJaxbFacade.newFacade().getUnmarshaller(true);
            JAXBElement<XmlPki> unmarshalled = (JAXBElement<XmlPki>) unmarshaller.unmarshal(is);
            return unmarshalled.getValue();
        }
    }

    private boolean checkPKIContainsCertificate(XmlPki pki, String certificationSubject) {
        return pki.getCertificate().stream().anyMatch(certificateType -> certificationSubject.equals(certificateType.getSubject()));
    }


}
