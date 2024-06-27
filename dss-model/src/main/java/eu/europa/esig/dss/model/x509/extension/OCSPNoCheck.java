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
 * RFC 6960. "4.2.2.2.1. Revocation Checking of an Authorized Responder"
 *      A CA may specify that an OCSP client can trust a responder for the
 *      lifetime of the responder's certificate.  The CA does so by
 *      including the extension id-pkix-ocsp-nocheck.  This SHOULD be a
 *      non-critical extension.  The value of the extension SHALL be NULL.
 *      CAs issuing such a certificate should realize that a compromise of
 *      the responder's key is as serious as the compromise of a CA key
 *      used to sign CRLs, at least for the validity period of this
 *      certificate.  CAs may choose to issue this type of certificate with
 *      a very short lifetime and renew it frequently.
 */
public class OCSPNoCheck extends CertificateExtension {

    private static final long serialVersionUID = 8531078272781544641L;

    /** Defines if the ocsp-nocheck extension is present and set to true */
    private boolean ocspNoCheckValue;

    /**
     * Default constructor
     */
    public OCSPNoCheck() {
        super(CertificateExtensionEnum.OCSP_NOCHECK.getOid());
    }

    /**
     * Returns the ocsp-nocheck extension value, when present
     *
     * @return the ocsp-nocheck extension value, FALSE is not present
     */
    public boolean isOcspNoCheck() {
        return ocspNoCheckValue;
    }

    /**
     * Sets the ocsp-nocheck extension value
     *
     * @param ocspNoCheckValue ocsp-nocheck extension value
     */
    public void setOcspNoCheck(boolean ocspNoCheckValue) {
        this.ocspNoCheckValue = ocspNoCheckValue;
    }

}
