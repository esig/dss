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
package eu.europa.esig.dss.model.x509.extension;

import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;

/**
 * RFC 9608 "No Revocation Available for X.509 Public Key Certificates"
 * The noRevAvail extension, defined in [X.509-2019-TC2], allows a CA to
 * indicate that no revocation information will be made available for
 * this certificate.
 * <p>
 * This extension MUST NOT be present in CA public key certificates.
 * <p>
 * Conforming CAs MUST include this extension in certificates for which
 * no revocation information will be published.  When present,
 * conforming CAs MUST mark this extension as non-critical.
 *
 */
public class NoRevAvail extends CertificateExtension {

    private static final long serialVersionUID = -488544490030463439L;

    /** Defines the value of noRevAvail extension */
    private boolean noRevAvailValue;

    /**
     * Default constructor
     */
    public NoRevAvail() {
        super(CertificateExtensionEnum.NO_REVOCATION_AVAILABLE.getOid());
    }

    /**
     * Returns the noRevAvail extension value
     *
     * @return TRUE if noRevAvail extension is present, FALSE otherwise
     */
    public boolean isNoRevAvail() {
        return noRevAvailValue;
    }

    /**
     * Sets the noRevAvail extension value
     *
     * @param noRevAvail whether noRevAvail extension is present
     */
    public void setNoRevAvail(boolean noRevAvail) {
        this.noRevAvailValue = noRevAvail;
    }

}
