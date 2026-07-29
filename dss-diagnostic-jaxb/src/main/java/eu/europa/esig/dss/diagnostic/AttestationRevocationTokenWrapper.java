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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAttestationRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.AttestationRevocationOrigin;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Wraps validation information of the attestation revocation token
 *
 */
public class AttestationRevocationTokenWrapper extends AbstractTokenProxy {

    /** Wrapped {@code XmlAttestationRevocationToken} */
    private final XmlAttestationRevocationToken attestationRevocationToken;

    /**
     * Default constructor
     *
     * @param attestationRevocationToken {@link XmlAttestationRevocationToken}
     */
    public AttestationRevocationTokenWrapper(XmlAttestationRevocationToken attestationRevocationToken) {
        Objects.requireNonNull(attestationRevocationToken, "XmlAttestationRevocationToken cannot be null!");
        this.attestationRevocationToken = attestationRevocationToken;
    }

    @Override
    protected XmlBasicSignature getCurrentBasicSignature() {
        return attestationRevocationToken.getBasicSignature();
    }

    @Override
    protected List<XmlChainItem> getCurrentCertificateChain() {
        return attestationRevocationToken.getCertificateChain();
    }

    @Override
    protected XmlSigningCertificate getCurrentSigningCertificate() {
        return attestationRevocationToken.getSigningCertificate();
    }

    /**
     * Returns FoundCertificatesProxy to access embedded certificates
     *
     * @return {@link FoundCertificatesProxy}
     */
    @Override
    public FoundCertificatesProxy foundCertificates() {
        return new FoundCertificatesProxy(attestationRevocationToken.getFoundCertificates());
    }

    /**
     * Gets origin of the attestation revocation token (e.g. EXTERNAL or CACHED)
     *
     * @return {@link AttestationRevocationOrigin}
     */
    public AttestationRevocationOrigin getOrigin() {
        return attestationRevocationToken.getOrigin();
    }

    /**
     * Gets the claimed type of the attestation revocation token
     *
     * @return {@link String}
     */
    public String getType() {
        return attestationRevocationToken.getType();
    }

    /**
     * Gets the location URI used to access the original attestation source token
     *
     * @return {@link String}
     */
    public String getSourceAddress() {
        return attestationRevocationToken.getSourceAddress();
    }

    /**
     * Gets the subject of the attestation revocation token
     *
     * @return {@link String}
     */
    public String getSubject() {
        return attestationRevocationToken.getSubject() != null ? attestationRevocationToken.getSubject().getValue() : null;
    }

    /**
     * Gets whether the subject of the attestation revocation token matches the subject of the related attestation
     *
     * @return TRUE if the subject matches, FALSE otherwise
     */
    public boolean getSubjectMatch() {
        return attestationRevocationToken.getSubject() != null && Boolean.TRUE.equals(attestationRevocationToken.getSubject().isMatch());
    }

    /**
     * Gets time of the issuance of the attestation revocation token
     *
     * @return {@link Date}
     */
    public Date getIssuedAt() {
        return attestationRevocationToken.getIssuedAt();
    }

    /**
     * Gets time of the expiration of the attestation revocation token
     *
     * @return {@link Date}
     */
    public Date getExpirationTime() {
        return attestationRevocationToken.getExpirationTime();
    }

    /**
     * Gets number of seconds after which a new attestation Status token should be requested
     *
     * @return {@link BigInteger}
     */
    public BigInteger getTimeToLive() {
        return attestationRevocationToken.getTimeToLive();
    }

    @Override
    public byte[] getBinaries() {
        return attestationRevocationToken.getBase64Encoded();
    }

    @Override
    public String getId() {
        return attestationRevocationToken.getId();
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (!(obj instanceof AttestationRevocationTokenWrapper))
            return false;
        AbstractTokenProxy other = (AbstractTokenProxy) obj;
        if (getId() == null) {
            if (other.getId() != null) {
                return false;
            }
        } else if (!getId().equals(other.getId())) {
            return false;
        }
        return true;
    }

}
