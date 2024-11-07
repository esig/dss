/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.test;

import eu.europa.esig.dss.pki.jaxb.JAXBPKILoader;
import eu.europa.esig.dss.pki.jaxb.PKIJaxbFacade;
import eu.europa.esig.dss.pki.jaxb.XmlPki;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.spi.x509.TrustedCertificateSource;
import jakarta.xml.bind.JAXBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * This class is used to facilitate JAXB PKI content loading in unit tests
 *
 */
public class JAXBPKICertificateLoader {

    private static final Logger LOG = LoggerFactory.getLogger(JAXBPKICertificateLoader.class);

    private final JAXBCertEntityRepository repository;

    private final JAXBPKILoader certificationEntityBuilder = new JAXBPKILoader();

    private final Set<String> createdPKIs = new HashSet<>();
    private final Map<String, XmlPki> filePkiMap = new HashMap<>();

    private String pkiFolder;

    private String[] pkiFilenames;

    private TrustedCertificateSource trustedCertificateSource;

    public JAXBPKICertificateLoader(JAXBCertEntityRepository repository) {
        this.repository = repository;
    }

    public void setTrustedCertificateSource(TrustedCertificateSource trustedCertificateSource) {
        this.trustedCertificateSource = trustedCertificateSource;
    }

    public void setPkiFolder(String pkiFolder) {
        this.pkiFolder = pkiFolder;
    }

    public void setPkiFilenames(String[] pkiFilenames) {
        this.pkiFilenames = pkiFilenames;
    }

    private void synchronizeCertificateSource() {
        if (trustedCertificateSource == null) {
            LOG.warn("No CommonTrustedCertificateSource to be synchronized");
            return;
        }
        repository.getTrustAnchors().stream().map(CertEntity::getCertificateToken).forEach(certificateToken -> trustedCertificateSource.addCertificate(certificateToken));
    }

    public CertEntity loadCertificateEntityFromXml(String certificateSubjectName) {
        CertEntity dbCertEntity = repository.getCertEntityBySubject(certificateSubjectName);
        dbCertEntity = getCertEntity(certificateSubjectName, dbCertEntity);
        return dbCertEntity;

    }

    public CertEntity loadCertificateEntityFromXml(Long serialNumber, String issuerSubjectName) {
        CertEntity dbCertEntity = repository.getCertEntityBySerialNumberAndParentSubject(serialNumber, issuerSubjectName);
        dbCertEntity = getCertEntity(issuerSubjectName, dbCertEntity);
        return dbCertEntity;
    }

    private CertEntity getCertEntity(String certificateSubjectName, CertEntity dbCertEntity) {
        if (dbCertEntity == null) {
            certificationEntityBuilder.persistPKI(repository, getPki(certificateSubjectName));

            dbCertEntity = repository.getCertEntityBySubject(certificateSubjectName);
            synchronizeCertificateSource();
        }
        if (dbCertEntity == null) {
            throw new RuntimeException("CertEntity not found");
        }
        return dbCertEntity;
    }

    public XmlPki getPki(String certificateSubject) {
        try {
            for (String filename : Objects.requireNonNull(pkiFilenames, "PKI filenames shall be defined!")) {
                String pkiFilePath = (pkiFolder != null ? pkiFolder : "") + "/" + filename;
                try (InputStream is = JAXBPKICertificateLoader.class.getResourceAsStream(pkiFilePath)) {
                    Objects.requireNonNull(is, String.format("Cannot find file %s", pkiFilePath));
                    if (createdPKIs.contains(filename)) {
                        continue;
                    }

                    XmlPki pki = processPKIFile(is, filename, certificateSubject);

                    if (pki != null) {
                        createdPKIs.add(filename);
                        return pki;
                    }
                }
            }

        } catch (IOException e) {
            fail("Unable to load PKI content folder.", e);
        }
        fail("Xml PKI factory content not found.");
        return null;
    }

    public XmlPki processPKIFile(InputStream is, String path, String certificateSubject) {
        XmlPki pki = filePkiMap.get(path);
        // map.get filePath
        if (pki == null) {
            pki = loadPKI(is, path);
            filePkiMap.put(path, pki);
        }
        if (checkPKIContainsCertificate(pki, certificateSubject)) {
            return pki;
        }
        return null;
    }

    private XmlPki loadPKI(InputStream inputStream, String pkiPath) {
        try (InputStream is = inputStream) {
            return PKIJaxbFacade.newFacade().unmarshall(is);
        } catch (JAXBException | IOException | SAXException | XMLStreamException e) {
            fail(String.format("Unable to load PKI XML : %s", pkiPath), e);
        }
        return null;
    }

    private boolean checkPKIContainsCertificate(XmlPki pki, String certificationSubject) {
        return pki.getCertificate().stream().anyMatch(certificateType -> certificationSubject.equals(certificateType.getSubject()));
    }

}
