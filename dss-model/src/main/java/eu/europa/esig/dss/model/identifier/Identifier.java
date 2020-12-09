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
package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * This class is used to obtain a unique id for an object
 */
public abstract class Identifier implements Serializable {

	private static final long serialVersionUID = 1440382536669604521L;

	/** The DigestAlgorithm to use */
	protected static final DigestAlgorithm DIGEST_ALGO = DigestAlgorithm.SHA256;

	/** The prefix to be added to a hexValue (e.g. "C-" +  HEX) */
	private final String prefix;

	/** The digest Id */
	private final Digest id;

	/** The String Id */
	private String xmlId;

	/**
	 * The constructor to get an identifier computed from a the binaries with a defined prefix
	 * 
	 * @param prefix {@link String} to be added in the beginning of a String identifier
	 * @param data a byte array to compute the identifier from
	 */
	protected Identifier(final String prefix, byte[] data) {
		Objects.requireNonNull(prefix, "Prefix cannot be null!");
		Objects.requireNonNull(data, "Data binaries cannot be null!");
		this.id = new Digest(DIGEST_ALGO, getMessageDigest(DIGEST_ALGO).digest(data));
		this.prefix = prefix;
	}

	/**
	 * The constructor to get an identifier computed provided digest with a defined prefix
	 * 
	 * @param prefix {@link String} to be added in the beginning of a String identifier
	 * @param digest {@link Digest} to use for a HEX value string
	 */
	protected Identifier(final String prefix, final Digest digest) {
		Objects.requireNonNull(prefix, "Prefix cannot be null!");
		Objects.requireNonNull(digest, "Digest cannot be null!");
		this.id = digest;
		this.prefix = prefix;
	}

	/**
	 * Gets {@code MessageDigest} of the DigestAlgorithm
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return {@link MessageDigest}
	 */
	protected MessageDigest getMessageDigest(DigestAlgorithm digestAlgorithm) {
		try {
			return digestAlgorithm.getMessageDigest();
		} catch (NoSuchAlgorithmException e) {
			throw new DSSException("Unable to create a MessageDigest for algorithm " + digestAlgorithm, e);
		}
	}

	/**
	 * Gets {@code Digest} Id
	 *
	 * @return {@link Digest}
	 */
	Digest getDigestId() {
		return id;
	}

	/**
	 * Return an ID conformant to XML Id
	 * 
	 * @return the XML encoded ID
	 */
	public String asXmlId() {
		if (xmlId == null) {
			xmlId = prefix != null ? prefix + id.getHexValue() : id.getHexValue();
		}
		return xmlId;
	}

	@Override
	public String toString() {
		return this.getClass().getSimpleName() + ":" + id;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Identifier other = (Identifier) obj;
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		} else if (!id.equals(other.id)) {
			return false;
		}
		return true;
	}

}
