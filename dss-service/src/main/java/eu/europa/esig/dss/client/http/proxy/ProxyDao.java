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
package eu.europa.esig.dss.client.http.proxy;

import java.util.Collection;

/**
 * Dao for the preferences of a Proxy
 *
 *
 *
 *
 *
 *
 */
public interface ProxyDao {

    /**
     * This method returns {@code ProxyPreference} for the given {@code ProxyKey}.
     *
     * @param id {@code ProxyKey}
     * @return
     */
    ProxyPreference get(final ProxyKey id);

    /**
     * This method returns the {@code Collection} of {@code ProxyPreference}(s).
     *
     * @return
     */
    Collection<ProxyPreference> getAll();

    /**
     * This method set a {@code ProxyPreference}.
     *
     * @param entity {@code ProxyPreference}
     */
    void update(final ProxyPreference entity);

}
