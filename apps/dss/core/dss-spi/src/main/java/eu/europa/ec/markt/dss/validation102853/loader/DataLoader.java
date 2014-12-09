/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.loader;

import java.io.Serializable;

import eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException;

/**
 * Component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
 *
 * @version $Revision$ - $Date$
 */

public interface DataLoader extends Serializable {

    /**
     * Execute a HTTP GET operation
     *
     * @param url to access
     * @return {@code byte} array of obtained data
     * @throws eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException
     */
    byte[] get(final String url) throws DSSCannotFetchDataException;

	/**
	 * Execute a HTTP GET operation with indication concerning the mandatory character of the operation.
	 *
	 * @param url to access
	 * @param refresh if true indicates that the cached data should be refreshed
	 * @return {@code byte} array of obtained data
	 * @throws eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException
	 */
	byte[] get(String url, boolean refresh) throws DSSCannotFetchDataException;

	/**
     * Executes a HTTP POST operation
     *
     * @param url to access
     * @param content
     * @return {@code byte} array of obtained data
     * @throws eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException
     */
    byte[] post(final String url, final byte[] content) throws DSSCannotFetchDataException;

    /**
     * This allows to set the content type. Example: Content-Type "application/ocsp-request"
     *
     * @param contentType to set
     */
    public void setContentType(final String contentType);
}
