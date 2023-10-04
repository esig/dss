package eu.europa.esig.dss.pki.repository;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;

import java.util.Map;

/**
 * This interface represents a repository for CertEntity objects.
 * It provides methods for querying and managing stored certificate entities.
 *
 * @param <T> {@code CertEntity} representing a repository entry.
 */
public interface CertEntityRepository<T extends CertEntity> {

    /**
     * Retrieves the certificate entity associated with the given certificate token.
     *
     * @param certificateToken The certificate token to search for.
     * @return The certificate entity associated with the provided token, or null if not found.
     */
    T getByCertificateToken(CertificateToken certificateToken);

    /**
     * Retrieves the revocation list associated with the parent certificate entity.
     *
     * @param parent The parent certificate entity.
     * @return A list containing the revocation entities associated with the parent certificate.
     */
    Map<T, CertEntityRevocation> getRevocationList(T parent);

    /**
     * Retrieves the revocation information for the given certificate entity.
     *
     * @param certEntity The certificate entity .
     * @return The revocation information  .
     */
    CertEntityRevocation getRevocation(T certEntity);

    /**
     * Retrieves the issuer certificate entity for the given certificate entity.
     *
     * @param certEntity The certificate entity.
     * @return The issuer certificate entity .
     */
    CertEntity getIssuer(T certEntity);

}
