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
package eu.europa.esig.dss.spi.eaa;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.enumerations.AttestationRevocationOrigin;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.TokenCertificateSource;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.util.Date;

/**
 * Represents an EAA revocation representation
 *
 */
public abstract class AttestationRevocationToken extends Token {

    private static final long serialVersionUID = 3803119761156101993L;

    /** Extracted binaries of the EAA Revocation Token */
    protected AttestationRevocationTokenBinary encoded;

    /** Signature used to sign the EAA revocation data */
    protected AdvancedSignature signature;

    /** Related {@link Attestation} to this status object */
    protected Attestation relatedAttestation;

    /** The URL which was used to obtain the revocation data (online). */
    protected String sourceURL;

    /** The external origin (EXTERNAL or CACHED) */
    protected AttestationRevocationOrigin origin;

    /** Contains the revocation status of the token. */
    protected AttestationStatus status;

    /** Certificate source built on the extracted information from the EAA revocation */
    protected TokenCertificateSource certificateSource;

    /**
     * Default constructor
     */
    protected AttestationRevocationToken() {
        // empty
    }

    /**
     * Sets a related EAA
     *
     * @param relatedAttestation {@link Attestation}
     */
    public void setRelatedEAA(Attestation relatedAttestation) {
        this.relatedAttestation = relatedAttestation;
    }

    /**
     * Gets the source URL used to access the status token
     *
     * @return {@link String}
     */
    public String getSourceURL() {
        return sourceURL;
    }

    /**
     * Sets the source URL used to access the status token
     *
     * @param sourceURL {@link String}
     */
    public void setSourceURL(String sourceURL) {
        this.sourceURL = sourceURL;
    }

    /**
     * Gets the origin of the status token (e.g. EXTERNAL or CACHED)
     *
     * @return {@link AttestationRevocationOrigin}
     */
    public AttestationRevocationOrigin getOrigin() {
        return origin;
    }

    /**
     * Sets the origin of the status token (e.g. EXTERNAL or CACHED)
     *
     * @param origin {@link AttestationRevocationOrigin}
     */
    public void setOrigin(AttestationRevocationOrigin origin) {
        this.origin = origin;
    }

    /**
     * Gets signature used to sign the EAA revocation token
     *
     * @return {@link AdvancedSignature}
     */
    public AdvancedSignature getSignature() {
        return signature;
    }

    /**
     * Gets the indication of the status of the related token (e.g. VALID, INVALID, etc.)
     *
     * @return {@link AttestationStatus}
     */
    public AttestationStatus getStatus() {
        return status;
    }

    /**
     * Gets the certificate source built on the extracted EAA revocation information
     *
     * @return {@link TokenCertificateSource}
     */
    public TokenCertificateSource getCertificateSource() {
        return certificateSource;
    }

    /**
     * Sets the certificate source built on the extracted EAA revocation information
     *
     * @param certificateSource {@link TokenCertificateSource}
     */
    public void setCertificateSource(TokenCertificateSource certificateSource) {
        this.certificateSource = certificateSource;
    }

    /**
     * Gets type of the token
     *
     * @return {@link String}
     */
    public String getType() {
        return signature != null ? signature.getSignatureType() : null;
    }

    /**
     * Gets subject of the token
     *
     * @return {@link String}
     */
    public String getSubject() {
        // not implemented by default
        return null;
    }

    /**
     * Gets whether the subject defined in the EAA revocation token matches the value defined in the EAA
     *
     * @return TRUE if the subject matches, FALSE otherwise. NULL if not supported.
     */
    public Boolean getSubjectMatch() {
        // not implemented by default
        return null;
    }

    /**
     * Gets expiration date of the token
     *
     * @return {@link Date}
     */
    public Date getExpirationDate() {
        // not implemented by default
        return null;
    }

    /**
     * Gets time in seconds when a consumer should request a new token after its extraction
     *
     * @return {@link Number}
     */
    public Number getTimeToLive() {
        // not implemented by default
        return null;
    }

    @Override
    protected TokenIdentifier buildTokenIdentifier() {
        return new AttestationRevocationTokenIdentifier(this);
    }

    @Override
    protected SignatureValidity checkIsSignedBy(PublicKey publicKey) {
        throw new UnsupportedOperationException(this.getClass().getName());
    }

    @Override
    public X500Principal getIssuerX500Principal() {
        if (signature.getSigningCertificateToken() != null) {
            return signature.getSigningCertificateToken().getSubject().getPrincipal();
        }
        return null;
    }

    /**
     * Gets the related EAA
     *
     * @return {@link Attestation}
     */
    public Attestation getRelatedEAA() {
        return relatedAttestation;
    }

    /**
     * Gets the {@code String} identifier of the related EAA
     *
     * @return {@link String}
     */
    public String getRelatedEAAId() {
        if (relatedAttestation != null) {
            return relatedAttestation.getId();
        }
        return null;
    }

    @Override
    public String toString(String indentStr) {
        // TODO : to be implemented
        return "";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.getBinaries();
    }

}
