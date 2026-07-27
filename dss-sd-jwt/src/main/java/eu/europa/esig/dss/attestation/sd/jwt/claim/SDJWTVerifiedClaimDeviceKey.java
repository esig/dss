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
package eu.europa.esig.dss.attestation.sd.jwt.claim;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDeviceKey;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.jwk.PublicJsonWebKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SD-JWT representation of a wallet holder's key as defined in RFC 7517 "JSON Web Key (JWK)".
 *
 */
public class SDJWTVerifiedClaimDeviceKey extends SDJWTVerifiedClaimMap implements VerifiedClaimDeviceKey {

    private static final long serialVersionUID = -579979170978240327L;

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTVerifiedClaimDeviceKey.class);

    /**
     * Cached instance of JWK
     */
    private PublicJsonWebKey publicJsonWebKey;

    /**
     * Constructor to initialize SDJWTClaimKey from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public SDJWTVerifiedClaimDeviceKey(VerifiedClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public PublicKey getPublicKey() {
        PublicJsonWebKey jwk = getPublicJsonWebKey();
        if (jwk != null) {
            return publicJsonWebKey.getPublicKey();
        }
        return null;
    }

    @Override
    public List<CertificateToken> getCertificates() {
        PublicJsonWebKey jwk = getPublicJsonWebKey();
        if (jwk != null) {
            List<X509Certificate> x5cCertificates = jwk.getCertificateChain();
            if (Utils.isCollectionNotEmpty(x5cCertificates)) {
                final List<CertificateToken> result = new ArrayList<>();
                for (X509Certificate x509Certificate : x5cCertificates) {
                    result.add(new CertificateToken(x509Certificate));
                }
                return result;
            }
        }
        return Collections.emptyList();
    }

    @Override
    public List<Digest> getCertificateDigests() {
        PublicJsonWebKey jwk = getPublicJsonWebKey();
        if (jwk != null) {
            final List<Digest> result = new ArrayList<>();
            String x509CertificateSha1Thumbprint = jwk.getX509CertificateSha1Thumbprint();
            if (Utils.isStringNotEmpty(x509CertificateSha1Thumbprint)) {
                result.add(new Digest(DigestAlgorithm.SHA1, DSSJsonUtils.fromBase64Url(x509CertificateSha1Thumbprint)));
            }
            String base64UrlSHA256Certificate = jwk.getX509CertificateSha256Thumbprint();
            if (Utils.isStringNotEmpty(base64UrlSHA256Certificate)) {
                result.add(new Digest(DigestAlgorithm.SHA256, DSSJsonUtils.fromBase64Url(base64UrlSHA256Certificate)));
            }
            return result;
        }
        return Collections.emptyList();
    }

    @Override
    public List<String> getCertificateKeyIdentifiers() {
        final List<String> result = new ArrayList<>();
        PublicJsonWebKey jwk = getPublicJsonWebKey();
        if (jwk != null && jwk.getKeyId() != null) {
            result.add(jwk.getKeyId());
        }
        VerifiedClaimString kid = getKID();
        if (kid != null) {
            result.add(kid.getStringValue());
        }
        return result;
    }

    @Override
    public List<String> getCertificateUrls() {
        final List<String> result = new ArrayList<>();
        PublicJsonWebKey jwk = getPublicJsonWebKey();
        if (jwk != null && jwk.getX509Url() != null) {
            result.add(jwk.getX509Url());
        }
        VerifiedClaimString jku = getJKU();
        if (jku != null) {
            result.add(jku.getStringValue());
        }
        return result;
    }

    /**
     * Gets the JWK claim representation
     *
     * @return {@link PublicJsonWebKey}
     */
    @SuppressWarnings("unchecked")
    protected PublicJsonWebKey getPublicJsonWebKey() {
        if (publicJsonWebKey == null) {
            try {
                VerifiedClaimMap jwk = getJWK();
                if (jwk == null) {
                    return null;
                }
                Object jwkObject = toJavaObject(jwk);
                if (jwkObject != null) {
                    publicJsonWebKey = PublicJsonWebKey.Factory.newPublicJwk((Map<String, Object>) jwkObject);
                }

            } catch (Exception e) {
                LOG.warn("Unable to parse JWK confirmation claim. Reason : {}", e.getMessage(), e);
            }
        }
        return publicJsonWebKey;
    }

    private Object toJavaObject(VerifiedClaim claim) {
        if (claim.isStringValueType()) {
            return claim.getStringValue();

        } else if (claim.isArrayValueType()) {
            final List<Object> javaList = new ArrayList<>();
            claim.getListValue().forEach(v -> {
                Object javaObject = toJavaObject(v);
                if (javaObject != null) {
                    javaList.add(javaObject);
                }
            });
            return javaList;

        } else if (claim.isMapValueType()) {
            final Map<String, Object> javaMap = new HashMap<>();
            for (Map.Entry<String, VerifiedClaim> claimEntry : claim.getMapValue().entrySet()) {
                Object javaObject = toJavaObject(claimEntry.getValue());
                if (javaObject != null) {
                    javaMap.put(claimEntry.getKey(), javaObject);
                }
            }
            return javaMap;

        } else {
            if (claim.getName() != null) {
                LOG.warn("The entry '{}' with value of type '{}' is not supported!", claim.getName(), claim.getClass().getSimpleName());
            } else {
                LOG.warn("The entry of type '{}' is not supported!", claim.getClass().getSimpleName());
            }
            return null;
        }
    }

    /**
     * Gets the JWK claim value containing the representation of the public key
     *
     * @return {@link VerifiedClaimMap}
     */
    public VerifiedClaimMap getJWK() {
        return getAsMap(SDJWTConstants.JWK);
    }

    /**
     * Gets the JWE claim value containing the representation of the encryption symmetric key
     *
     * @return {@link VerifiedClaimString}
     */
    public VerifiedClaimString getJWE() {
        return getAsString(SDJWTConstants.JWE);
    }

    /**
     * Gets the JWK claim value containing the representation of the key identifier claim
     *
     * @return {@link VerifiedClaimString}
     */
    public VerifiedClaimString getKID() {
        return getAsString(SDJWTConstants.KID);
    }

    /**
     * Gets the JWK claim value containing the representation of the URL where
     * the signing certificate can be downloaded from
     *
     * @return {@link VerifiedClaimString}
     */
    public VerifiedClaimString getJKU() {
        return getAsString(SDJWTConstants.JKU);
    }

    @Override
    public List<String> getAuthorizedNamespaces() {
        // not applicable
        return Collections.emptyList();
    }

    @Override
    public Map<String, List<String>> getAuthorizedDataElements() {
        // not applicable
        return Collections.emptyMap();
    }

}
