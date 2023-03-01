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
 * 4.2.1.14.  Inhibit anyPolicy
 *    The inhibit anyPolicy extension can be used in certificates issued to
 *    CAs.  The inhibit anyPolicy extension indicates that the special
 *    anyPolicy OID, with the value { 2 5 29 32 0 }, is not considered an
 *    explicit match for other certificate policies except when it appears
 *    in an intermediate self-issued CA certificate.
 */
public class InhibitAnyPolicy extends CertificateExtension {

    private static final long serialVersionUID = 872144242608534696L;

    /**
     * Indicates the number of additional non-self-issued certificates that may appear
     * in the path before anyPolicy is no longer permitted.
     */
    private int value = -1;

    /**
     * Default constructor
     */
    public InhibitAnyPolicy() {
        super(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid());
    }

    /**
     * Gets the InhibitAnyPolicy constraint value
     *
     * @return requireExplicitPolicy int value if present, -1 otherwise
     */
    public int getValue() {
        return value;
    }

    /**
     * Sets the InhibitAnyPolicy constraint value
     *
     * @param value int InhibitAnyPolicy value
     */
    public void setValue(int value) {
        this.value = value;
    }

}
