package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.EncapsulatedRevocationTokenIdentifier;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.revocation.RevocationRef;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * Generates a String identifier for a given token (e.g. {@code eu.europa.esig.dss.validation.AdvancedSignature},
 * {@code eu.europa.esig.dss.model.x509.CertificateToken}, etc.).
 *
 * Caches the calculated values and takes care of duplicates
 */
public interface TokenIdentifierProvider {

    /**
     * Gets a {@code String} identifier for a given {@code AdvancedSignature}
     *
     * @param signature {@link AdvancedSignature} to get String id for
     * @return {@link String}
     */
    String getIdAsString(AdvancedSignature signature);

    /**
     * Gets a {@code String} identifier for a given {@code Token}
     *
     * @param token {@link Token} to get String id for
     * @return {@link String}
     */
    String getIdAsString(Token token);

    /**
     * Gets a {@code String} identifier for a given {@code SignatureScope}
     *
     * @param signatureScope {@link SignatureScope} to get String id for
     * @return {@link String}
     */
    String getIdAsString(SignatureScope signatureScope);

    /**
     * Gets a {@code String} identifier for a given {@code TLInfo}
     *
     * @param tlInfo {@link TLInfo} to get String id for
     * @return {@link String}
     */
    String getIdAsString(TLInfo tlInfo);

    /**
     * Gets a {@code String} identifier for a given {@code CertificateRef}
     *
     * @param certificateRef {@link CertificateRef} to get String id for
     * @return {@link String}
     */
    String getIdAsString(CertificateRef certificateRef);

    /**
     * Gets a {@code String} identifier for a given {@code RevocationRef}
     *
     * @param revocationRef {@link RevocationRef} to get String id for
     * @return {@link String}
     */
    String getIdAsString(RevocationRef<?> revocationRef);

    /**
     * Gets a {@code String} identifier for a given {@code EncapsulatedRevocationTokenIdentifier}
     *
     * @param revocationIdentifier {@link EncapsulatedRevocationTokenIdentifier} to get String id for
     * @return {@link String}
     */
    String getIdAsString(EncapsulatedRevocationTokenIdentifier<?> revocationIdentifier);

}
