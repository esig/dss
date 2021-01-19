package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;

/**
 * Generates a String identifier for a given token (e.g. {@code eu.europa.esig.dss.validation.AdvancedSignature},
 * {@code eu.europa.esig.dss.model.x509.CertificateToken}, etc.).
 *
 * Caches the calculated values and takes care of duplicates
 */
public interface TokenIdentifierProvider {

    /**
     * Gets a {@code String} identifier for a given object
     *
     * @param object {@link IdentifierBasedObject} to get String id for
     * @return {@link String}
     */
    String getIdAsString(IdentifierBasedObject object);

}
