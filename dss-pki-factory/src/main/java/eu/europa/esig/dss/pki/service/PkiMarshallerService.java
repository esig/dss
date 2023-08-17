package eu.europa.esig.dss.pki.service;

import eu.europa.esig.dss.pki.config.JaxbConfig;
import eu.europa.esig.dss.pki.dto.CertDto;
import eu.europa.esig.dss.pki.exception.Error404Exception;
import eu.europa.esig.dss.pki.wrapper.CertificateWrapper;
import eu.europa.esig.dss.pki.wrapper.EntityId;
import eu.europa.esig.pki.manifest.CertificateType;
import eu.europa.esig.pki.manifest.Pki;

import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;


public class PkiMarshallerService {

    private static JaxbConfig unmarshaller;
    private static PkiMarshallerService pkiMarshallerService;

    public static PkiMarshallerService getInstance() {
        if (pkiMarshallerService == null) {
            synchronized (PkiMarshallerService.class) {
                pkiMarshallerService = new PkiMarshallerService();
                unmarshaller = new JaxbConfig();
            }
        }
        return pkiMarshallerService;
    }

    private PkiMarshallerService() {

    }

    private Map<String, Pki> pkis = new HashMap<>();

    public void init(InputStream is, String fileName) throws IOException, JAXBException {
        Pki pki = (Pki) unmarshaller.unmarshaller().unmarshal(new StreamSource(is));
        String key = removeExtension(fileName);
        if (pkis.containsKey(key)) {
            throw new RuntimeException("Duplicate entry : " + key);
        } else {
            pkis.put(key, pki);
        }
    }

    public void resetPKIs() {
        pkis = new HashMap<>();
    }

    public Collection<Pki> getPKIs() {
        return pkis.values();
    }

    public Set<String> getPKIKeys() {
        return pkis.keySet();
    }

    public Map<Integer, List<CertDto>> getPKIDto(String id) {
        Pki currentPki = pkis.get(id);
        if (currentPki == null) {
            throw new Error404Exception("PKI '" + id + "' not found");
        }

        Map<Integer, List<CertDto>> result = new HashMap<>();

        List<CertificateWrapper> certWrappers = new ArrayList<>();
        List<CertificateType> pkiCertificates = currentPki.getCertificate();
        for (CertificateType cert : pkiCertificates) {
            CertificateWrapper issuer = getIssuer(new EntityId(cert.getIssuer()), certWrappers);
            String issuerName = issuer != null ? issuer.getSubject() : cert.getSubject();
            certWrappers.add(new CertificateWrapper(cert, issuerName));
        }

        for (CertificateWrapper cert : certWrappers) {
            int level = getLevel(cert, certWrappers);
            List<CertDto> list = result.computeIfAbsent(level, k -> new ArrayList<>());
            CertDto dto = convert(cert, certWrappers);
            list.add(dto);
        }

        return result;
    }

    private int getLevel(CertificateWrapper cert, List<CertificateWrapper> certificates) {
        List<CertificateWrapper> crossCerts = getPossibleCrossCertificates(cert, certificates);
        if (crossCerts.size() > 1) {
            return getMaxLevel(crossCerts, certificates);
        } else {
            CertificateWrapper issuer = find(cert.getIssuer(), certificates);
            if (!issuer.getKey().equals(cert.getKey())) {
                return 1 + getLevel(issuer, certificates);
            }
            return 0;
        }
    }

    private int getMaxLevel(List<CertificateWrapper> crossCerts, List<CertificateWrapper> certificates) {
        int max = 0;
        for (CertificateWrapper crossCert : crossCerts) {
            CertificateWrapper issuer = find(crossCert.getIssuer(), certificates);
            if (!issuer.getKey().equals(crossCert.getKey())) {
                int issuerLevel = 1 + getLevel(issuer, certificates);
                if (issuerLevel > max) {
                    max = issuerLevel;
                }
            }
        }
        return max;
    }

    private List<CertificateWrapper> getPossibleCrossCertificates(CertificateWrapper cert, List<CertificateWrapper> certificates) {
        List<CertificateWrapper> result = new ArrayList<>();
        for (CertificateWrapper c : certificates) {
            if (c.getSubject().equals(cert.getSubject())) {
                result.add(c);
            }
        }
        return result;
    }

    private List<String> getCrossCertKeys(CertificateWrapper cert, List<CertificateWrapper> certificates) {
        List<String> keys = new ArrayList<>();
        List<CertificateWrapper> possibleCrossCertificates = getPossibleCrossCertificates(cert, certificates);
        for (CertificateWrapper certificateWrapper : possibleCrossCertificates) {
            if (!certificateWrapper.getKey().equals(cert.getKey())) {
                keys.add(getStringKey(certificateWrapper.getKey()));
            }
        }
        return keys;
    }

    private CertificateWrapper find(EntityId issuerKey, List<CertificateWrapper> certificates) {
        for (CertificateWrapper cert : certificates) {
            if (issuerKey.equals(cert.getKey())) {
                return cert;
            }
        }
        throw new IllegalStateException("Parent not found " + issuerKey);
    }

    private CertDto convert(CertificateWrapper cert, List<CertificateWrapper> certificates) {
        CertDto dto = new CertDto();
        dto.setKey(getStringKey(cert.getKey()));
        dto.setName(cert.getSubject());
        dto.setIssuerKey(getStringKey(cert.getIssuer()));
        dto.setIssuerName(getIssuer(cert, certificates).getSubject());
        dto.setCrossCertKeys(getCrossCertKeys(cert, certificates));
        dto.setTsa(cert.isTSA());
        dto.setOcsp(cert.isOcspNoCheck());
        dto.setRevoked(cert.getRevocationDate() != null);
        dto.setExpired(cert.getNotAfter().before(new Date()));
        dto.setTrustAnchor(cert.isTrustAnchor());
        dto.setToBeIgnored(cert.isToBeIgnored());
        return dto;
    }

    private CertificateWrapper getIssuer(CertificateWrapper cert, List<CertificateWrapper> certificates) {
        if (cert.getKey().equals(cert.getIssuer())) {
            return cert;
        }
        return getIssuer(cert.getIssuer(), certificates);
    }

    private CertificateWrapper getIssuer(EntityId issuerId, List<CertificateWrapper> certificates) {
        for (CertificateWrapper issuerCandidate : certificates) {
            if (issuerCandidate.getKey().equals(issuerId)) {
                return issuerCandidate;
            }
        }
        return null;
    }

    private String getStringKey(EntityId id) {
        return id.getIssuerName() + "-" + id.getSerialNumber().longValue();
    }

    private String removeExtension(String fileName) {
        if (fileName == null) {
            return null;
        } else {
            return fileName.substring(0, fileName.lastIndexOf('.'));
        }
    }

}
