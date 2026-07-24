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
package eu.europa.esig.dss.eaa.revocation.model.statuslist;

import eu.europa.esig.dss.enumerations.AttestationStatus;
import eu.europa.esig.dss.spi.eaa.AttestationRevocationToken;
import eu.europa.esig.dss.spi.eaa.AttestationRevocationTokenBinary;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.CertificateSource;

import java.io.Serializable;
import java.util.Date;

/**
 * Represents a validated Token Status List response against a given EAA
 *
 */
public class TokenStatusList extends AttestationRevocationToken {

    private static final long serialVersionUID = -471820238992127908L;

    /** Payload of the Token Status List */
    protected StatusListPayload payload;

    /**
     * Constructor to instantiate the EAA Status List object from a builder
     *
     * @param builder {@link TokenStatusListBuilder}
     */
    protected TokenStatusList(TokenStatusListBuilder builder) {
        this.encoded = builder.binary;
        this.signature = builder.signature;
        this.status = builder.status;
        this.payload = builder.payload;
    }

    /**
     * Instantiates a new builder to create the EAAStatusToken
     *
     * @return {@link TokenStatusListBuilder}
     */
    public static TokenStatusListBuilder initBuilder() {
        return new TokenStatusListBuilder();
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
     * Builder to create the EAA Status Token
     *
     */
    public static class TokenStatusListBuilder implements Serializable {

        private static final long serialVersionUID = -5818532413563116918L;

        /** Extracted binaries of the Status Token */
        protected AttestationRevocationTokenBinary binary;

        /** Signature used to sign the EAA revocation data */
        protected AdvancedSignature signature;

        /** Contains the revocation status of the token. */
        protected AttestationStatus status;

        /** Payload of the Token Status List */
        protected StatusListPayload payload;

        /** Certificate source built on the extracted information from the EAA revocation */
        protected CertificateSource certificateSource;

        /**
         * Default constructor
         */
        protected TokenStatusListBuilder() {
            // empty
        }

        /**
         * Sets binaries of the revocation token
         *
         * @param binary {@link AttestationRevocationTokenBinary}
         * @return this {@link TokenStatusListBuilder}
         */
        public TokenStatusListBuilder setBinary(AttestationRevocationTokenBinary binary) {
            this.binary = binary;
            return this;
        }

        /**
         * Sets signature used to sign this token
         *
         * @param signature {@link AdvancedSignature}
         * @return this {@link TokenStatusListBuilder}
         */
        public TokenStatusListBuilder setSignature(AdvancedSignature signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sets the status value for the corresponding EAA
         *
         * @param status {@link AttestationStatus}
         * @return this {@link TokenStatusListBuilder}
         */
        public TokenStatusListBuilder setStatus(AttestationStatus status) {
            this.status = status;
            return this;
        }

        /**
         * Sets the payload of the revocation token
         *
         * @param payload {@link StatusListPayload}
         * @return this {@link TokenStatusListBuilder}
         */
        public TokenStatusListBuilder setPayload(StatusListPayload payload) {
            this.payload = payload;
            return this;
        }

        /**
         * Sets the certificate source
         *
         * @param certificateSource {@link CertificateSource}
         * @return this {@link TokenStatusListBuilder}
         */
        public TokenStatusListBuilder setCertificateSource(CertificateSource certificateSource) {
            this.certificateSource = certificateSource;
            return this;
        }

        /**
         * Builds the {@link TokenStatusList}
         *
         * @return {@link TokenStatusList}
         */
        public TokenStatusList build() {
            return new TokenStatusList(this);
        }

    }

}
