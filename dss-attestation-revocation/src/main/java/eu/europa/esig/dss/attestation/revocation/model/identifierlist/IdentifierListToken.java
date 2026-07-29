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
package eu.europa.esig.dss.attestation.revocation.model.identifierlist;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationToken;
import eu.europa.esig.dss.spi.attestation.AttestationRevocationTokenBinary;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.io.Serializable;
import java.util.Date;

/**
 * Represents a validated token containing revocation information for an attestation provided as an Identifier List
 *
 */
public class IdentifierListToken extends AttestationRevocationToken {

    private static final long serialVersionUID = -471820238992127908L;

    /** Payload of the Token Status List */
    protected IdentifierListPayload payload;

    /**
     * Constructor to instantiate the attestation Status List object from a builder
     *
     * @param builder {@link IdentifierListTokenBuilder}
     */
    protected IdentifierListToken(IdentifierListTokenBuilder builder) {
        this.encoded = builder.binary;
        this.signature = builder.signature;
        this.status = builder.status;
        this.payload = builder.payload;
    }

    /**
     * Instantiates a new builder to create the attestationStatusToken
     *
     * @return {@link IdentifierListTokenBuilder}
     */
    public static IdentifierListTokenBuilder initBuilder() {
        return new IdentifierListTokenBuilder();
    }

    @Override
    public String getSubject() {
        return payload != null ? payload.getSubject() : null;
    }

    @Override
    public Boolean getSubjectMatch() {
        return sourceURL != null && sourceURL.equals(getSubject());
    }

    @Override
    public Date getCreationDate() {
        return payload != null ? payload.getIssuedAt() : null;
    }

    @Override
    public Date getExpirationDate() {
        return payload != null ? payload.getExpirationTime() : null;
    }

    @Override
    public Number getTimeToLive() {
        return payload != null ? payload.getTimeToLive() : null;
    }

    /**
     * Builder to create the Identifier List
     *
     */
    public static class IdentifierListTokenBuilder implements Serializable {

        private static final long serialVersionUID = -5818532413563116918L;

        /** Extracted binaries of the Status Token */
        protected AttestationRevocationTokenBinary binary;

        /** Signature used to sign the attestation revocation data */
        protected AdvancedSignature signature;

        /** Contains the revocation status of the token. */
        protected AttestationStatus status;

        /** Payload of the Token Status List */
        protected IdentifierListPayload payload;

        /** Certificate source built on the extracted information from the attestation revocation */
        protected CertificateSource certificateSource;

        /**
         * Default constructor
         */
        protected IdentifierListTokenBuilder() {
            // empty
        }

        /**
         * Sets binaries of the revocation token
         *
         * @param binary {@link AttestationRevocationTokenBinary}
         * @return this {@link IdentifierListTokenBuilder}
         */
        public IdentifierListTokenBuilder setBinary(AttestationRevocationTokenBinary binary) {
            this.binary = binary;
            return this;
        }

        /**
         * Sets signature used to sign this token
         *
         * @param signature {@link AdvancedSignature}
         * @return this {@link IdentifierListTokenBuilder}
         */
        public IdentifierListTokenBuilder setSignature(AdvancedSignature signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sets the revocation value for the corresponding attestation
         *
         * @param status {@link AttestationStatus}
         * @return this {@link IdentifierListTokenBuilder}
         */
        public IdentifierListTokenBuilder setStatus(AttestationStatus status) {
            this.status = status;
            return this;
        }

        /**
         * Sets the payload of the revocation token
         *
         * @param payload {@link IdentifierListPayload}
         * @return this {@link IdentifierListTokenBuilder}
         */
        public IdentifierListTokenBuilder setPayload(IdentifierListPayload payload) {
            this.payload = payload;
            return this;
        }

        /**
         * Sets the certificate source
         *
         * @param certificateSource {@link CertificateSource}
         * @return this {@link IdentifierListTokenBuilder}
         */
        public IdentifierListTokenBuilder setCertificateSource(CertificateSource certificateSource) {
            this.certificateSource = certificateSource;
            return this;
        }

        /**
         * Builds the {@link IdentifierListToken}
         *
         * @return {@link IdentifierListToken}
         */
        public IdentifierListToken build() {
            return new IdentifierListToken(this);
        }

    }

}
