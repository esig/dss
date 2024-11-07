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
package eu.europa.esig.dss.spi.x509.tsp;

import java.io.Serializable;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;

/**
 * Abstraction of a Time Stamping authority which delivers RFC 3161 Time Stamp Responses containing tokens, from Time
 * Stamp Requests.
 *
 */
public interface TSPSource extends Serializable {

	/**
	 * Gets a TimeStampResponse relevant to the provided digest
	 *
	 * @param digestAlgorithm
	 *            the used digest algorithm
	 * @param digest
	 *            the computed digest to be timestamped
	 * @return {@link TimestampBinary} binary of a signed timestamp token
	 * @throws DSSException
	 *             if any error occurred
	 */
	TimestampBinary getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException;

}
