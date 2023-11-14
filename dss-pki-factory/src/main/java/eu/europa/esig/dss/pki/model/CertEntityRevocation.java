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
package eu.europa.esig.dss.pki.model;


import eu.europa.esig.dss.enumerations.RevocationReason;

import java.util.Date;

/**
 * This class represents the revocation information for a certificate.
 */
public class CertEntityRevocation {

    /** The revocation time of the certificate */
    private final Date revocationDate;

    /** The revocation reason */
    private final RevocationReason revocationReason;

    /**
     * Constructs a new Revocation instance with the provided revocation date and reason.
     *
     * @param revocationDate {@link Date} the date of revocation.
     * @param revocationReason {@link Date} the reason for revocation.
     */
    public CertEntityRevocation(Date revocationDate, RevocationReason revocationReason) {
        this.revocationDate = revocationDate;
        this.revocationReason = revocationReason;
    }

    /**
     * Retrieves the date of revocation.
     *
     * @return The date of revocation.
     */
    public Date getRevocationDate() {
        return revocationDate;
    }

    /**
     * Retrieves the reason for revocation.
     *
     * @return The reason for revocation.
     */
    public RevocationReason getRevocationReason() {
        return revocationReason;
    }

}
