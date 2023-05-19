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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;

import java.util.Date;

/**
 * This class fitlers Trusted Services by the related MRA equivalence starting date
 *
 */
public class ServiceByMRAEquivalenceStartingDateFilter extends AbstractTrustedServiceFilter {

    /** Time to filter by */
    private final Date date;

    /**
     * Default constructor
     *
     * @param date {@link Date} to filter TrustedServices with a valid MRA equivalence starting time
     */
    public ServiceByMRAEquivalenceStartingDateFilter(Date date) {
        this.date = date;
    }

    @Override
    boolean isAcceptable(TrustedServiceWrapper service) {
        Date startDate = service.getMraTrustServiceEquivalenceStatusStartingTime();
        if (startDate == null || date == null) {
            return false;
        }

        Date endDate = service.getMraTrustServiceEquivalenceStatusEndingTime();
        return !date.before(startDate) && (endDate == null || !date.after(endDate));
    }

}
