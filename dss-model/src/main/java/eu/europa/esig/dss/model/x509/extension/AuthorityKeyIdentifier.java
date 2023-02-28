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

/**
 * 4.2.1.1.  Authority Key Identifier
 *    The authority key identifier extension provides a means of
 *    identifying the public key corresponding to the private key used to
 *    sign a certificate.  This extension is used where an issuer has
 *    multiple signing keys (either due to multiple concurrent key pairs or
 *    due to changeover).  The identification MAY be based on either the
 *    key identifier (the subject key identifier in the issuer's
 *    certificate) or the issuer name and serial number.
 */
public class AuthorityKeyIdentifier extends CertificateExtension {

    private static final long serialVersionUID = -4382641249022016152L;

    /** Key identifier property */
    private byte[] keyIdentifier;

    /** DER-encoded representation of combination of authorityCertIssuer and authorityCertSerialNumber parameters */
    private byte[] authorityCertIssuerSerial;

    /**
     * Default constructor
     */
    public AuthorityKeyIdentifier() {
        super(CertificateExtensionEnum.AUTHORITY_KEY_IDENTIFIER.getOid());
    }

    /**
     * Returns the key identifier
     *
     * @return byte array
     */
    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * Sets the key identifier
     *
     * @param keyIdentifier byte array
     */
    public void setKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    /**
     * Gets the DER-encoded IssuerSerial built on authorityCertIssuer and authorityCertSerialNumber parameters
     *
     * @return DER-encoded authority cert issuer
     */
    public byte[] getAuthorityCertIssuerSerial() {
        return authorityCertIssuerSerial;
    }

    /**
     * Sets the DER-encoded IssuerSerial built on authorityCertIssuer and authorityCertSerialNumber parameters
     *
     * @param authorityCertIssuerSerial DER-encoded authority cert issuer
     */
    public void setAuthorityCertIssuerSerial(byte[] authorityCertIssuerSerial) {
        this.authorityCertIssuerSerial = authorityCertIssuerSerial;
    }

}
