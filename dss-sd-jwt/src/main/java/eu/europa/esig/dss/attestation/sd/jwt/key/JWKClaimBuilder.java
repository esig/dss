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
package eu.europa.esig.dss.attestation.sd.jwt.key;

import eu.europa.esig.dss.attestation.common.key.PublicKeyInfo;
import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaim;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimArray;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * Builds a JWK claim, as specified in RFC 7517 "JSON Web Key (JWK)".
 * NOTE: The builder does not verify validity of the provided configuration.
 * See {@code <a href="https://ec.europa.eu/digital-building-blocks/tracker/browse/DSS-3959">DSS-3959</a>}
 *
 */
public class JWKClaimBuilder {

    /**
     * JWK key type (RFC 7517 "kty").
     * <p>
     * Used when the JWK represents a certificate reference (x5c, x5t#S256, x5u)
     * instead of a public key representation.
     */
    private String keyType;

    /**
     * Public key representation used to build a JWK containing the subject public key.
     * <p>
     * When provided, the JWK contains the corresponding key parameters (EC, OKP or RSA)
     * and certificate-related parameters shall not be present.
     */
    private PublicKeyInfo publicKeyInfo;

    /**
     * Certificate chain represented through the RFC 7517 {@code x5c} parameter.
     * <p>
     * This option is mutually exclusive with {@code publicKeyInfo},
     * {@code certificateThumbprint} and {@code x5u}.
     */
    private List<CertificateToken> certificateChain;

    /**
     * SHA-256 certificate thumbprint represented through the RFC 7517
     * {@code x5t#S256} parameter.
     * <p>
     * This option can optionally be combined with {@code x5u}.
     */
    private Digest certificateThumbprint;

    /**
     * Certificate URL represented through the RFC 7517 {@code x5u} parameter.
     * <p>
     * According to the SD-JWT attestation specification, this parameter shall only be
     * present together with {@code x5t#S256}.
     */
    private String x5u;

    /**
     * Default constructor
     */
    public JWKClaimBuilder() {
        // empty
    }

    /**
     * Defines the JWK key type ({@code kty}).
     * <p>
     * This value is required when the JWK represents a certificate reference
     * instead of a public key.
     *
     * @param keyType {@link String} the JWK key type
     * @return this builder
     */
    public JWKClaimBuilder keyType(String keyType) {
        this.keyType = keyType;
        return this;
    }

    /**
     * Defines the public key information to be represented in the JWK.
     *
     * @param publicKeyInfo {@link PublicKeyInfo}
     * @return this builder
     */
    public JWKClaimBuilder publicKeyInfo(PublicKeyInfo publicKeyInfo) {
        this.publicKeyInfo = publicKeyInfo;
        return this;
    }

    /**
     * Defines the certificate chain to be represented through the {@code x5c}
     * parameter.
     *
     * @param certificateChain a list of {@link CertificateToken}s
     * @return this builder
     */
    public JWKClaimBuilder certificateChain(List<CertificateToken> certificateChain) {
        this.certificateChain = certificateChain;
        return this;
    }

    /**
     * Defines the certificate thumbprint to be represented through the
     * {@code x5t#S256} parameter.
     *
     * @param certificateThumbprint {@link Digest} of certificate thumbprint
     * @return this builder
     */
    public JWKClaimBuilder certificateThumbprint(Digest certificateThumbprint) {
        this.certificateThumbprint = certificateThumbprint;
        return this;
    }

    /**
     * Defines the certificate URL to be represented through the {@code x5u}
     * parameter.
     *
     * @param x5u {@link String} the certificate URL
     * @return this builder
     */
    public JWKClaimBuilder x5u(String x5u) {
        this.x5u = x5u;
        return this;
    }

    /**
     * Builds the {@code jwk} claim according to RFC 7517 and the SD-JWT
     * specification.
     * The resulting claim contains either:
     * - a representation of the attestation subject public key; or
     * - a representation of the attestation subject certificate.
     *
     * @return the generated {@link SDJWTClaim}
     */
    public SDJWTClaim create() {
        final SDJWTClaimObject jwk = SDJWTClaim.createObject(SDJWTConstants.JWK);

        if (publicKeyInfo != null) {
            jwk.addChild(SDJWTClaim.create(SDJWTConstants.KTY, publicKeyInfo.getKeyType()));

            if (publicKeyInfo instanceof PublicKeyInfo.ECKey) {
                createEC(jwk, (PublicKeyInfo.ECKey) publicKeyInfo);
            } else if (publicKeyInfo instanceof PublicKeyInfo.OKPKey) {
                createOKP(jwk, (PublicKeyInfo.OKPKey) publicKeyInfo);
            } else if (publicKeyInfo instanceof PublicKeyInfo.RSAKey) {
                createRSA(jwk, (PublicKeyInfo.RSAKey) publicKeyInfo);
            } else {
                throw new UnsupportedOperationException(String.format(
                        "Unsupported key info type: '%s'", publicKeyInfo.getClass().getSimpleName()));
            }
        }
        if (Utils.isCollectionNotEmpty(certificateChain)) {
            SDJWTClaimArray x5c = SDJWTClaim.createArray(SDJWTConstants.X5C);
            certificateChain.forEach(c -> x5c.addElement(SDJWTClaim.create(DSSJsonUtils.toBase64Url(c.getEncoded()))));
            jwk.addChild(x5c);
        }
        if (certificateThumbprint != null) {
            if (DigestAlgorithm.SHA256 != certificateThumbprint.getAlgorithm()) {
                throw new UnsupportedOperationException(String.format(
                        "Only SHA256 is supported for a device key representation within 'jwk' claim! " +
                                "Found algorithm : %s", certificateThumbprint.getAlgorithm()));
            }
            jwk.addChild(SDJWTClaim.create(SDJWTConstants.X5TS526, DSSJsonUtils.toBase64Url(certificateThumbprint.getValue())));
        }
        if (x5u != null) {
            jwk.addChild(SDJWTClaim.create(SDJWTConstants.X5U, x5u));
        }

        if (Utils.isCollectionEmpty(jwk.getChildren())) {
            throw new NullPointerException("No configuration has been present for the attestation subject public key or " +
                    "certificate representation!");
        }

        if (publicKeyInfo == null && keyType != null) {
            jwk.addChild(SDJWTClaim.create(SDJWTConstants.KTY, keyType));
        }

        return jwk;
    }

    private void createEC(SDJWTClaimObject jwk, PublicKeyInfo.ECKey publicKeyInfo) {
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.EC_CRV, publicKeyInfo.getCurve().getLabel()));
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.EC_X, DSSJsonUtils.toBase64Url(publicKeyInfo.getX())));
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.EC_Y, DSSJsonUtils.toBase64Url(publicKeyInfo.getY())));
    }

    private void createOKP(SDJWTClaimObject jwk, PublicKeyInfo.OKPKey publicKeyInfo) {
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.OKP_CRV, publicKeyInfo.getCurve().getLabel()));
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.OKP_X, DSSJsonUtils.toBase64Url(publicKeyInfo.getX())));
    }

    private void createRSA(SDJWTClaimObject jwk, PublicKeyInfo.RSAKey publicKeyInfo) {
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.RSA_N, DSSJsonUtils.toBase64Url(publicKeyInfo.getModulus())));
        jwk.addChild(SDJWTClaim.create(SDJWTConstants.RSA_E, DSSJsonUtils.toBase64Url(publicKeyInfo.getExponent())));
    }

}
