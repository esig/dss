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
 * 4.2.1.9.  Basic Constraints
 *    The basic constraints extension identifies whether the subject of the
 *    certificate is a CA and the maximum depth of valid certification
 *    paths that include this certificate.
 */
public class BasicConstraints extends CertificateExtension {

    private static final long serialVersionUID = -2670814551087982603L;

    /**
     * Defines whether the certificate is a CA certificate
     */
    private boolean ca;

    /**
     * Gives the maximum number of non-self-issued intermediate certificates that
     * may follow this certificate in a valid certification path
     */
    private int pathLenConstraint;

    /**
     * Default constructor
     */
    public BasicConstraints() {
        super(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid());
    }

    /**
     * Returns whether the certificate is a CA certificate
     *
     * @return TRUE if the certificate is a CA certificate, FALSE otherwise
     */
    public boolean isCa() {
        return ca;
    }

    /**
     * Sets whether the certificate is a CA certificate
     *
     * @param ca TRUE if the certificate is a CA certificate, FALSE otherwise
     */
    public void setCa(boolean ca) {
        this.ca = ca;
    }

    /**
     * Returns the pathLenConstraint value
     *
     * @return the pathLenConstraint value
     */
    public int getPathLenConstraint() {
        return pathLenConstraint;
    }

    /**
     * Sets the pathLenConstraint value
     *
     * @param pathLenConstraint the pathLenConstraint value
     */
    public void setPathLenConstraint(int pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

}
