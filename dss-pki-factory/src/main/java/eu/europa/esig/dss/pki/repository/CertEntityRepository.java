package eu.europa.esig.dss.pki.repository;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.model.DBCertEntity;
import eu.europa.esig.dss.pki.model.Revocation;
import org.bouncycastle.cert.X509CertificateHolder;

import java.util.List;
import java.util.Map;

/**
 * This interface represents a repository for CertEntity objects.
 * It provides methods for querying and managing certificate entities stored in the db.
 *
 * @param <T> The type of CertEntity, which should be a subclass of CertEntity.
 */
public interface CertEntityRepository<T extends CertEntity> {

    /**
     * Retrieves a list of CertEntity objects that have the specified parent.
     *
     * @param parent The parent CertEntity whose children are to be retrieved.
     * @return A list of CertEntity objects that have the specified parent.
     */
    List<T> getByParent(T parent);

    /**
     * Retrieves a list of all CertEntity objects in the repository.
     *
     * @return A list of all CertEntity objects in the repository.
     */
    List<T> getAll();

    /**
     * Retrieves the CertEntity with the specified serial number and parent subject.
     *
     * @param serialNumber The serial number of the CertEntity to be retrieved.
     * @param idCA         The subject (distinguished name) of the parent CertEntity.
     * @return The CertEntity with the specified serial number and parent subject.
     */
    T getOneBySerialNumberAndParentSubject(Long serialNumber, String idCA);

    /**
     * Retrieves a list of CertEntity objects that have a null parent.
     *
     * @return A list of CertEntity objects that have a null parent.
     */
    List<T> getByParentNull();

    /**
     * Retrieves a list of CertEntity objects that have the trust anchor flag set to true.
     *
     * @return A list of CertEntity objects that have the trust anchor flag set to true.
     */
    List<T> getByTrustAnchorTrue();

    /**
     * Retrieves a list of CertEntity objects that have the trust anchor flag set to true and match the specified PKI name.
     *
     * @param name The name of the PKI (Public Key Infrastructure) for which trust anchor certificates are to be retrieved.
     * @return A list of CertEntity objects that have the trust anchor flag set to true and match the specified PKI name.
     */
    List<T> getByTrustAnchorTrueAndPkiName(String name);

    /**
     * Retrieves a list of CertEntity objects that have the toBeIgnored flag set to true.
     *
     * @return A list of CertEntity objects that have the toBeIgnored flag set to true.
     */
    List<T> getByToBeIgnoredTrue();

    /**
     * Retrieves a list of unique names of end entities (leaf certificates) stored in the repository.
     *
     * @return A list of unique names of end entities (leaf certificates).
     */
    List<String> getEndEntityNames();

    /**
     * Retrieves a list of unique names of Timestamping Authorities (TSAs) stored in the repository.
     *
     * @return A list of unique names of Timestamping Authorities (TSAs).
     */
    List<String> getTsaNames();

    /**
     * Retrieves a list of unique names of OCSP (Online Certificate Status Protocol) responders stored in the repository.
     *
     * @return A list of unique names of OCSP responders.
     */
    List<String> getOcspNameList();

    /**
     * Retrieves a list of unique names of Certification Authorities (CAs) stored in the repository.
     *
     * @return A list of unique names of Certification Authorities (CAs).
     */
    List<String> getCaNameList();

    /**
     * Retrieves a list of unique names of Certificates stored in the repository.
     *
     * @return A list of unique names of Certificates.
     */
    List<String> getCertNameList();

    /**
     * Retrieves a list of CertEntity objects that have the specified subject (distinguished name).
     *
     * @param id The subject (distinguished name) of the CertEntity to be retrieved.
     * @return A list of CertEntity objects that have the specified subject.
     */
    List<T> getBySubject(String id);

    /**
     * Retrieves the PSS (Probabilistic Signature Scheme) status of the CertEntity with the specified subject.
     *
     * @param id The subject (distinguished name) of the CertEntity.
     * @return The PSS status of the CertEntity with the specified subject.
     */
    boolean getPss(String id);

    /**
     * Saves the specified CertEntity in the repository.
     *
     * @param certEntity The CertEntity to be saved in the repository.
     * @return The saved CertEntity.
     */
    T save(T certEntity);

    /**
     * Retrieves the certificate entity with the specified ID from the data store.
     *
     * @param id The ID of the certificate entity to retrieve.
     * @return The certificate entity matching the provided ID, or null if not found.
     */
    T getCertEntity(String id);


    /**
     * Retrieves the certificate entity associated with the given certificate token.
     *
     * @param certificateToken The certificate token to search for.
     * @return The certificate entity associated with the provided token, or null if not found.
     */
    T getByCertificateToken(CertificateToken certificateToken);

    /**
     * Converts the given certificate entity to an X509CertificateHolder.
     *
     * @param certEntity The certificate entity to convert.
     * @return An X509CertificateHolder representing the certificate entity.
     */
    X509CertificateHolder convertToX509CertificateHolder(T certEntity);

    /**
     * Retrieves the certificate chain associated with the provided certificate entity.
     *
     * @param certEntity The certificate entity.
     * @return An array of X509CertificateHolder representing the certificate chain.
     */
    X509CertificateHolder[] getCertificateChain(T certEntity);

    /**
     * Retrieves the revocation list associated with the parent certificate entity.
     *
     * @param parent The parent certificate entity.
     * @return A list containing the revocation entities associated with the parent certificate.
     */
    Map<T, Revocation> getRevocationList(T parent);

    /**
     * Retrieves the revocation information for the given certificate entity.
     *
     * @param certEntity The certificate entity .
     * @return The revocation information  .
     */
    Revocation getRevocation(T certEntity);

    /**
     * Retrieves the revocation information for the given certificate token.
     *
     * @param certificateToken The certificate token for which to retrieve revocation information.
     * @return The revocation information .
     */
    Revocation getRevocation(CertificateToken certificateToken);

    /**
     * Retrieves the issuer certificate entity for the given certificate entity.
     *
     * @param certEntity The certificate entity.
     * @return The issuer certificate entity .
     */
    CertEntity getIssuer(T certEntity);
}
