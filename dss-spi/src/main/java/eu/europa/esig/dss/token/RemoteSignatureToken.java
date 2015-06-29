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

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
public abstract class RemoteSignatureToken implements SignatureTokenConnection {
	@Override
	public void close() {

	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {
		return null;
	}

	@Override
	public byte[] sign(byte[] bytes, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry keyEntry) throws DSSException {

		return sign(bytes, digestAlgorithm);
	}

	/**
	 * @param bytes           The array of bytes to be signed
	 * @param digestAlgorithm The digest algorithm to use to create the hash to sign
	 * @return The array of bytes representing the signature value
	 * @throws DSSException If there is any problem during the signature process
	 */
	public abstract byte[] sign(byte[] bytes, DigestAlgorithm digestAlgorithm) throws DSSException;
}
