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

import java.util.Collection;
import java.util.Collections;
import java.util.Date;

/**
 * Creates filters for trusted entity services filtering
 *
 */
public final class TrustedEntitiesFilterFactory {

    /**
     * Default constructor
     */
    private TrustedEntitiesFilterFactory() {
        // empty
    }

    /**
     * Creates a TrustedEntityService filter by list Url
     *
     * @param url {@link String} URL to filter trusted services by
     * @return {@link TrustedEntityServiceFilter}
     */
    public static TrustedEntityServiceFilter createFilterByListUrl(String url) {
        return new ServiceByTrustedEntityServiceUrlFilter(Collections.singleton(url));
    }

    /**
     * Creates a TrustedEntityService filter by list urls
     *
     * @param urls a collection of {@link String}s to filter trusted services by
     * @return {@link TrustedEntityServiceFilter}
     */
    public static TrustedEntityServiceFilter createFilterByListUrls(Collection<String> urls) {
        return new ServiceByTrustedEntityServiceUrlFilter(urls);
    }

    /**
     * Creates a TrustedEntityService filter by date
     *
     * @param date {@link Date} to filter trusted services by
     * @return {@link TrustedEntityServiceFilter}
     */
    public static TrustedEntityServiceFilter createFilterByDate(Date date) {
        return new TrustedEntityServiceByDateFilter(date);
    }

    /**
     * Creates a TrustedEntityService filter by STI URI
     *
     * @param stiUri {@link String} to filter trusted services by STI URI
     * @return {@link TrustedEntityServiceFilter}
     */
    public static TrustedEntityServiceFilter createFilterByServiceTypeIdentifierUri(String stiUri) {
        return new TrustedEntityServiceByStiFilter(stiUri);
    }

    /**
     * Creates a TrustedEntityService filter by service status URI
     *
     * @param statusUri {@link String} to filter trusted services by service status URI
     * @return {@link TrustedEntityServiceFilter}
     */
    public static TrustedEntityServiceFilter createFilterByServiceStatusUri(String statusUri) {
        return new TrustedEntityServiceByStatusFilter(statusUri);
    }

}
