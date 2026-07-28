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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedEntityServiceWrapper;

/**
 * Filters trusted entity services by a status URI
 *
 */
public class TrustedEntityServiceByStatusFilter extends AbstractTrustedEntityServiceFilter {

    /** Service Status Uri to filter by */
    private final String statusUri;

    /**
     * Default constructor
     *
     * @param statusUri {@link String} to filter Trusted Services with the given status
     */
    public TrustedEntityServiceByStatusFilter(String statusUri) {
        this.statusUri = statusUri;
    }

    @Override
    protected boolean isAcceptable(TrustedEntityServiceWrapper service) {
        // if Status is NULL, it means no history entries are present, thus all services are valid
        if (statusUri == null) {
            return service.getStatus() == null;
        }
        return statusUri.equals(service.getStatus());
    }

}
