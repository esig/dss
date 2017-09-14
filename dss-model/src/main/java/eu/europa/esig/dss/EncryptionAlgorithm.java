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
package eu.europa.esig.dss;

import java.util.HashMap;
import java.util.Map;

/**
 * Supported signature encryption algorithms.
 */
public enum EncryptionAlgorithm {

	RSA("RSA", "1.2.840.113549.1.1.1", "RSA/ECB/PKCS1Padding"),

	DSA("DSA", "1.2.840.10040.4.1", "DSA"),

	ECDSA("ECDSA", "1.2.840.10045.2.1", "ECDSA"),

	HMAC("HMAC", "", "");

	private String name;
	private String oid;
	private String padding;

	private static class Registry {

		private static final Map<String, EncryptionAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();

		private static Map<String, EncryptionAlgorithm> registerOIDAlgorithms() {
			Map<String, EncryptionAlgorithm> map = new HashMap<String, EncryptionAlgorithm>();
			for (EncryptionAlgorithm encryptionAlgorithm : values()) {
				map.put(encryptionAlgorithm.oid, encryptionAlgorithm);
			}
			return map;
		}
	}

	/**
	 * Returns the encryption algorithm associated to the given OID.
	 *
	 * @param oid
	 *            the ASN1 algorithm OID
	 * @return the linked encryption algorithm
	 * @throws DSSException
	 *             if the oid doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forOID(String oid) throws DSSException {
		EncryptionAlgorithm algorithm = Registry.OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the encryption algorithm name
	 * @return the linked encryption algorithm
	 * @throws DSSException
	 *             if the name doesn't match any algorithm
	 */
	public static EncryptionAlgorithm forName(final String name) throws DSSException {
		// To be checked if ECC exists also .
		if ("EC".equals(name) || "ECC".equals(name)) {
			return ECDSA;
		}

		try {
			return valueOf(name);
		} catch (Exception e) {
			throw new DSSException("Unsupported algorithm: " + name);
		}
	}

	/**
	 * Returns the encryption algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the encryption algorithm name
	 * @param defaultValue
	 *            The default value for the {@code EncryptionAlgorithm}
	 * @return the corresponding {@code EncryptionAlgorithm} or the default value
	 */
	public static EncryptionAlgorithm forName(final String name, final EncryptionAlgorithm defaultValue) {
		// To be checked if ECC exists also .
		if ("EC".equals(name) || "ECC".equals(name)) {
			return ECDSA;
		}

		try {
			final EncryptionAlgorithm encryptionAlgorithm = valueOf(name);
			return encryptionAlgorithm;
		} catch (Exception e) {
			return defaultValue;
		}
	}

	private EncryptionAlgorithm(String name, String oid, String padding) {
		this.name = name;
		this.oid = oid;
		this.padding = padding;
	}

	/**
	 * Get the algorithm name
	 * 
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the ASN1 algorithm OID
	 * 
	 * @return the OID
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Get the algorithm padding
	 * 
	 * @return the padding
	 */
	public String getPadding() {
		return padding;
	}

}
