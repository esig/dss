/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.model.x509.CertificateToken;

/**
 * Abstract implementation of a certificate extension
 *
 */
public class CertificateExtension implements OidDescription {

    private static final long serialVersionUID = 580856406397002942L;

    /** The corresponding OID of the certificate extension */
    private final String oid;

    /** The user-friendly label (optional) */
    private String description;

    /** Defines whether the certificate extension is critical or not */
    private boolean critical;

    /** DER-encoded octets of the certificate extension */
    private byte[] octets;

    /**
     * Constructor with a certificate extension OID
     *
     * @param oid {@link String} certificate extension OID
     */
    public CertificateExtension(final String oid) {
        this.oid = oid;
    }

    /**
     * Constructor from a {@code CertificateExtensionEnum}
     *
     * @param certificateExtensionEnum {@link CertificateExtensionEnum}
     */
    public CertificateExtension(CertificateExtensionEnum certificateExtensionEnum) {
        this.oid = certificateExtensionEnum.getOid();
        this.description = certificateExtensionEnum.getDescription();
    }

    @Override
    public String getOid() {
        return oid;
    }

    @Override
    public String getDescription() {
        return description;
    }

    /**
     * Returns whether the certificate extension is critical or not
     *
     * @return TRUE if the certificate extension is critical, FALSE otherwise
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * Checks and sets whether the certificate extension is critical
     *
     * @param certificateToken {@link CertificateToken} to check
     */
    public void checkCritical(CertificateToken certificateToken) {
        this.critical = certificateToken.getCertificate().getCriticalExtensionOIDs().contains(oid);
    }

    /**
     * Returns DER-encoded octets of the certificate extension
     *
     * @return byte array containing DER-encoded octets of the certificate extension
     */
    public byte[] getOctets() {
        return octets;
    }

    /**
     * Sets DER-encoded octets of the certificate extension
     *
     * @param octets byte array containing DER-encoded octets of the certificate extension
     */
    public void setOctets(byte[] octets) {
        this.octets = octets;
    }

}
