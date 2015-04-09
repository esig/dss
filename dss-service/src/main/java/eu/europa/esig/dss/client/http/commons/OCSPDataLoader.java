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
package eu.europa.esig.dss.client.http.commons;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of DataLoader using HttpClient. More flexible for HTTPS without having to add the certificate to the JVM TrustStore.
 *
 *
 */
public class OCSPDataLoader extends CommonsDataLoader {

    private static final Logger LOG = LoggerFactory.getLogger(OCSPDataLoader.class);

    public static final String OCSP_CONTENT_TYPE = "application/ocsp-request";

    /**
     * The default constructor for CommonsDataLoader.
     */
    public OCSPDataLoader() {
        super(OCSP_CONTENT_TYPE);
    }

    /**
     * In case of OCSPDataLoader the contentType is fixed to: Content-Type "application/ocsp-request"
     *
     * @param contentType
     */
    @Override
    public void setContentType(final String contentType) {

        // do nothing: in case of OCSPDataLoader the contentType is fixed.
    }
}
