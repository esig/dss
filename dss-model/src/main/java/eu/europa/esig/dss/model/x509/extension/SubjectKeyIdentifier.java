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
 * 4.2.1.2.  Subject Key Identifier
 *    The subject key identifier extension provides a means of identifying
 *    certificates that contain a particular public key.
 */
public class SubjectKeyIdentifier extends CertificateExtension {

    private static final long serialVersionUID = -187448404652061938L;

    /** The subject key identifier */
    private byte[] ski;

    /**
     * Default constructor
     */
    public SubjectKeyIdentifier() {
        super(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid());
    }

    /**
     * Returns the subject key identifier
     *
     * @return byte array
     */
    public byte[] getSki() {
        return ski;
    }

    /**
     * Sets the subject key identifier
     *
     * @param ski byte array
     */
    public void setSki(byte[] ski) {
        this.ski = ski;
    }

}
