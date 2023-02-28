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
package eu.europa.esig.dss.token.predicate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

import java.util.Date;
import java.util.Objects;

/**
 * This predicate is used to filter keys based on the validity range of the certificate
 *
 */
public class ValidAtTimeKeyEntryPredicate implements DSSKeyEntryPredicate {

    /** Represents the validation time to check the certificate validity range against */
    private final Date validationTime;

    /**
     * Constructor instantiating the object with the current time
     */
    public ValidAtTimeKeyEntryPredicate() {
        this(new Date());
    }

    /**
     * Default constructor with the defined validation time
     *
     * @param validationTime {@link Date} representing a time to check the validity range of the certificate against
     *                                (i.e. notBefore - notAfter). If the time is outside the validity range for
     *                                the corresponding certificate, the key is not returned.
     */
    public ValidAtTimeKeyEntryPredicate(Date validationTime) {
        Objects.requireNonNull(validationTime, "Validation time cannot be null!");
        this.validationTime = validationTime;
    }

    @Override
    public boolean test(DSSPrivateKeyEntry dssPrivateKeyEntry) {
        CertificateToken certificate = dssPrivateKeyEntry.getCertificate();
        if (certificate != null) {
            return validationTime.compareTo(certificate.getNotBefore()) >= 0 &&
                    validationTime.compareTo(certificate.getNotAfter()) <= 0;
        }
        return false;
    }

}
