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
package eu.europa.esig.dss.token;

import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public interface RemoteSignatureTokenConnection {

	/**
	 * Retrieves all the available keys (private keys entries) from the token.
	 *
	 * @return List of encapsulated private keys
	 * @throws DSSException
	 *                      If there is any problem during the retrieval process
	 */
	List<RemoteKeyEntry> getKeys() throws DSSException;

	/**
	 * Retrieves a key by its alias
	 * 
	 * @param alias
	 *            the key alias to retrieve
	 * 
	 * @return the RemoteKeyEntry with the given alias
	 * 
	 */
	RemoteKeyEntry getKey(String alias) throws DSSException;

	/**
	 * This method signs the {@code toBeSigned} data with the digest
	 * {@code digestAlgorithm} and the given {@code alias}.
	 * 
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param digestAlgorithm
	 *                        The digest algorithm to be used before signing
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 * @throws DSSException
	 *                      If there is any problem during the signature process
	 */
	SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException;

	/**
	 * This method signs the {@code toBeSigned} data with the digest
	 * {@code digestAlgorithm}, the mask {@code mgf} and the given {@code alias}.
	 * 
	 * @param toBeSigned
	 *                        The data that need to be signed
	 * @param digestAlgorithm
	 *                        The digest algorithm to be used before signing
	 * @param mgf
	 *                        the mask generation function
	 * @param alias
	 *                        The key alias to be used
	 * @return The array of bytes representing the signature value
	 * @throws DSSException
	 *                      If there is any problem during the signature process
	 */
	SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, String alias) throws DSSException;

}
