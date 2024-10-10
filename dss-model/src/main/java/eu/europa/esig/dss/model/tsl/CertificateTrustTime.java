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
package eu.europa.esig.dss.model.tsl;

import eu.europa.esig.dss.model.timedependent.BaseTimeDependent;

import java.util.Date;
import java.util.Objects;

/**
 * This class defines a validity period during which a certificate is considered as a trust anchor
 *
 */
public class CertificateTrustTime extends BaseTimeDependent {

    /** Defines whether the current object identifies a trusted certificate */
    private final boolean trusted;

    /**
     * Constructor to create either a not trusted or indefinitely trusted entry
     *
     * @param trusted whether the object corresponds to a trusted certificate token
     */
    public CertificateTrustTime(final boolean trusted) {
        this.trusted = trusted;
    }

    /**
     * Default constructor
     *
     * @param startDate {@link Date} certificate trust start time
     * @param endDate {@link Date} certificate trust end time
     */
    public CertificateTrustTime(final Date startDate, final Date endDate) {
        super(startDate, endDate);
        this.trusted = true;
    }

    /**
     * Returns whether the corresponding certificate has a trusted period
     *
     * @return TRUE if the certificate has a trusted period, FALSE otherwise
     */
    public boolean isTrusted() {
        return trusted;
    }

    /**
     * This method verifies whether the {@code controlTime} lies within the certificate trust time range
     *
     * @param controlTime {@link Date} to check
     * @return TRUE if the certificate is trusted during the {@code controlTime}, FALSE otherwise
     */
    public boolean isTrustedAtTime(Date controlTime) {
        return isTrusted() && Objects.equals(getDateBefore(getStartDate(), controlTime), getStartDate()) &&
                Objects.equals(getDateAfter(getEndDate(), controlTime), getEndDate());
    }

    /**
     * This method is used to create a joint time period using the current trust time and the given period
     * between {@code startDate} and {@code endDate}.
     * NOTE: the method does not change the current time, but creates a new joint interval
     *
     * @param startDate {@link Date} the time of another period start
     * @param endDate {@link Date} the time of another period end
     * @return {@link CertificateTrustTime}
     */
    public CertificateTrustTime getJointTrustTime(Date startDate, Date endDate) {
        return new CertificateTrustTime(getDateBefore(getStartDate(), startDate), getDateAfter(getEndDate(), endDate));
    }

    private Date getDateBefore(Date dateOne, Date dateTwo) {
        if (dateOne == null) {
            return dateOne;
        } else if (dateTwo == null) {
            return dateTwo;
        } else if (dateOne.before(dateTwo)) {
            return dateOne;
        } else {
            return dateTwo;
        }
    }

    private Date getDateAfter(Date dateOne, Date dateTwo) {
        if (dateOne == null) {
            return dateOne;
        } else if (dateTwo == null) {
            return dateTwo;
        } else if (dateOne.after(dateTwo)) {
            return dateOne;
        } else {
            return dateTwo;
        }
    }

}
