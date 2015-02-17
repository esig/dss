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

package eu.europa.ec.markt.dss.signature.token;

import java.util.List;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * Connection through available API to the SSCD (SmartCard, MSCAPI, PKCS#12)
 *
 * @version $Revision$ - $Date$
 */

public interface SignatureTokenConnection {

	/**
	 * Closes the connection to the SSCD.
	 */
	void close();

	/**
	 * Retrieves all the available keys (private keys entries) from the SSCD.
	 *
	 * @return List of encapsulated private keys
	 * @throws DSSException If there is any problem during the retrieval process
	 */
	List<DSSPrivateKeyEntry> getKeys() throws DSSException;

	/**
	 * @param bytes           The array of bytes that need to be signed
	 * @param digestAlgorithm The digest algorithm to be used before signing
	 * @param keyEntry        The private key to be used
	 * @return The array of bytes representing the signature value
	 * @throws DSSException If there is any problem during the signature process
	 */
	byte[] sign(final byte[] bytes, final DigestAlgorithm digestAlgorithm, final DSSPrivateKeyEntry keyEntry) throws DSSException;
}