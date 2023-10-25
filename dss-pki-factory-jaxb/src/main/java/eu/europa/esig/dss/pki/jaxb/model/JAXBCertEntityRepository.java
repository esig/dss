package eu.europa.esig.dss.pki.jaxb.model;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JAXB PKI implementation of {@code CertEntityRepository}
 *
 */
public class JAXBCertEntityRepository implements CertEntityRepository<JAXBCertEntity> {

    private static final Logger LOG = LoggerFactory.getLogger(JAXBCertEntityRepository.class);

    /** A set of all CertEntities */
    private final Set<JAXBCertEntity> certEntities = new LinkedHashSet<>();

    /**
     * Default constructor
     */
    public JAXBCertEntityRepository() {
        // empty
    }

    /**
     * Returns all cert entries from the repository
     *
     * @return a list of {@link JAXBCertEntity}s
     */
    public List<JAXBCertEntity> getAll() {
        return new ArrayList<>(certEntities);
    }

    /**
     * Gets a cert entity for the given serial number and an issuer distinguished name
     *
     * @param serialNumber {@link Long} serial number of the certificate
     * @param issuerName {@link String} issuer certificate's distinguished name
     * @return {@link JAXBCertEntity}
     */
    public JAXBCertEntity getCertEntityBySerialNumberAndParentSubject(Long serialNumber, String issuerName) {
        List<JAXBCertEntity> certEntityList = certEntities.stream().filter(
                dbCertEntity -> dbCertEntity.getSerialNumber().equals(serialNumber) &&
                        dbCertEntity.getIssuer().getSubject().equals(issuerName)).collect(Collectors.toList());
        return certEntityList.stream().findFirst().orElse(null);
    }

    /**
     * Returns a list of all trust anchors from the repository
     *
     * @return a list of {@link JAXBCertEntity}s
     */
    public List<JAXBCertEntity> getTrustAnchors() {
        return certEntities.stream().filter(JAXBCertEntity::isTrustAnchor).collect(Collectors.toList());
    }

    /**
     * Retrieves a list of {@code JAXBCertEntity} for the given JAXB PKI name
     *
     * @param name {@link String} name of the PKI
     * @return a list of {@link JAXBCertEntity}s
     */
    public List<JAXBCertEntity> getByPkiName(String name) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getPkiName().equals(name)).collect(Collectors.toList());
    }

    /**
     * Gets a list of cert entities by the given subject distinguished name
     *
     * @param subjectName {@link String} certificate subject distinguished name to match
     * @return a list of {@link JAXBCertEntity}s
     */
    public List<JAXBCertEntity> getBySubject(String subjectName) {
        return certEntities.stream().filter(dbCertEntity -> dbCertEntity.getSubject().equals(subjectName)).collect(Collectors.toList());
    }

    /**
     * Gets a single cert entity with the given {@code subjectName}.
     * If more than one cert entity with the given subject DN is found, returns the matching first entry.
     *
     * @param subjectName {@link String} certificate subject distinguished name to match
     * @return {@link JAXBCertEntity}
     */
    public JAXBCertEntity getCertEntityBySubject(String subjectName) {
        List<JAXBCertEntity> certEntity = this.getBySubject(subjectName);
        if (certEntity == null || certEntity.size() == 0) {
            LOG.warn("Certificate '" + subjectName + "' not found");
            return null;
        }
        if (certEntity.size() > 1) {
            LOG.warn("More than one result (returns first)");
        }
        return certEntity.get(0);
    }

    /**
     * Adds a new {@code JAXBCertEntity} to the repository
     *
     * @param dbCertEntity {@link JAXBCertEntity} to add
     * @return {@link JAXBCertEntity} that have been added
     */
    public boolean save(JAXBCertEntity dbCertEntity) {
        return certEntities.add(dbCertEntity);
    }

    @Override
    public Map<JAXBCertEntity, CertEntityRevocation> getRevocationList(JAXBCertEntity parent) {
        return certEntities.stream()
                .filter(dbCertEntity -> dbCertEntity.getRevocationDate() != null && parent.equals(dbCertEntity.getIssuer()))
                .collect(Collectors.toMap(
                        dbCertEntity -> dbCertEntity,
                        dbCertEntity -> new CertEntityRevocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason())
                ));
    }

    @Override
    public CertEntityRevocation getRevocation(JAXBCertEntity dbCertEntity) {
        if (dbCertEntity.getRevocationDate() != null) {
            return new CertEntityRevocation(dbCertEntity.getRevocationDate(), dbCertEntity.getRevocationReason());
        } else return null;
    }

    @Override
    public CertEntity getIssuer(JAXBCertEntity certEntity) {
        return certEntity.getIssuer();
    }

    @Override
    public JAXBCertEntity getByCertificateToken(CertificateToken certificateToken) {
        List<JAXBCertEntity> certEntityList = certEntities.stream()
                .filter(c -> certificateToken.equals(c.getCertificateToken())).collect(Collectors.toList());
        return certEntityList.stream().findFirst().orElse(null);
    }

}
