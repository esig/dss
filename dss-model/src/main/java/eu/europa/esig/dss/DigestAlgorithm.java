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
 * Supported Algorithms
 *
 */
public enum DigestAlgorithm {

	// see DEPRECATED http://www.w3.org/TR/2012/WD-xmlsec-algorithms-20120105/
	// see http://www.w3.org/TR/2013/NOTE-xmlsec-algorithms-20130411/
	// @formatter:off
	SHA1("SHA1", "SHA-1", "1.3.14.3.2.26", "http://www.w3.org/2000/09/xmldsig#sha1", 20),

	SHA224("SHA224", "SHA-224", "2.16.840.1.101.3.4.2.4", "http://www.w3.org/2001/04/xmldsig-more#sha224", 28),

	SHA256("SHA256", "SHA-256", "2.16.840.1.101.3.4.2.1", "http://www.w3.org/2001/04/xmlenc#sha256", 32),

	SHA384("SHA384", "SHA-384", "2.16.840.1.101.3.4.2.2", "http://www.w3.org/2001/04/xmldsig-more#sha384", 48),

	SHA512("SHA512", "SHA-512", "2.16.840.1.101.3.4.2.3", "http://www.w3.org/2001/04/xmlenc#sha512", 64),

	// see https://tools.ietf.org/html/rfc6931
	SHA3_224("SHA3-224", "SHA3-224", "2.16.840.1.101.3.4.2.7", "http://www.w3.org/2007/05/xmldsig-more#sha3-224", 28),

	SHA3_256("SHA3-256", "SHA3-256", "2.16.840.1.101.3.4.2.8", "http://www.w3.org/2007/05/xmldsig-more#sha3-256", 32),

	SHA3_384("SHA3-384", "SHA3-384", "2.16.840.1.101.3.4.2.9", "http://www.w3.org/2007/05/xmldsig-more#sha3-384", 48),

	SHA3_512("SHA3-512", "SHA3-512", "2.16.840.1.101.3.4.2.10", "http://www.w3.org/2007/05/xmldsig-more#sha3-512", 64),

	RIPEMD160("RIPEMD160", "RIPEMD160", "1.3.36.3.2.1", "http://www.w3.org/2001/04/xmlenc#ripemd160"),

	MD2("MD2", "MD2", "1.2.840.113549.2.2", "http://www.w3.org/2001/04/xmldsig-more#md2"),

	MD5("MD5", "MD5", "1.2.840.113549.2.5", "http://www.w3.org/2001/04/xmldsig-more#md5");
	/**
	 * RFC 2313
	 * "MD2", "1.2.840.113549.2.2"
	 * "MD4", "1.2.840.113549.2.4"
	 * "MD5", "1.2.840.113549.2.5"
	 */
	// @formatter:on

	private final String name;
	private final String javaName;
	private final String oid;
	private final String xmlId;
	/* In case of MGF usage */
	private final int saltLength;

	private static class Registry {

		private static final Map<String, DigestAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();
		private static final Map<String, DigestAlgorithm> XML_ALGORITHMS = registerXMLAlgorithms();
		private static final Map<String, DigestAlgorithm> ALGORITHMS = registerAlgorithms();

		private static Map<String, DigestAlgorithm> registerOIDAlgorithms() {
			final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();
			for (final DigestAlgorithm digestAlgorithm : values()) {
				map.put(digestAlgorithm.oid, digestAlgorithm);
			}
			return map;
		}

		private static Map<String, DigestAlgorithm> registerXMLAlgorithms() {
			final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();
			for (final DigestAlgorithm digestAlgorithm : values()) {
				map.put(digestAlgorithm.xmlId, digestAlgorithm);
			}
			return map;
		}

		private static Map<String, DigestAlgorithm> registerAlgorithms() {
			final Map<String, DigestAlgorithm> map = new HashMap<String, DigestAlgorithm>();
			for (final DigestAlgorithm digestAlgorithm : values()) {
				map.put(digestAlgorithm.name, digestAlgorithm);
			}
			return map;
		}
	}

	/**
	 * Returns the digest algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the algorithm name
	 * @return the digest algorithm linked to the given name
	 * @throws DSSException
	 *             if the given name doesn't match any algorithm
	 */
	public static DigestAlgorithm forName(final String name) throws DSSException {
		final DigestAlgorithm algorithm = Registry.ALGORITHMS.get(name);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + name + "/" + name);
		}
		return algorithm;
	}

	/**
	 * Returns the digest algorithm associated to the given JCE name.
	 *
	 * @param name
	 *            the algorithm name
	 * @param defaultValue
	 *            The default value for the {@code DigestAlgorithm}
	 * @return the corresponding {@code DigestAlgorithm} or the default value
	 */
	public static DigestAlgorithm forName(final String name, final DigestAlgorithm defaultValue) {
		final DigestAlgorithm algorithm = Registry.ALGORITHMS.get(name);
		if (algorithm == null) {
			return defaultValue;
		}
		return algorithm;
	}

	/**
	 * Returns the digest algorithm associated to the given OID.
	 *
	 * @param oid
	 *            the algorithm oid
	 * @return the digest algorithm linked to the oid
	 * @throws DSSException
	 *             if the oid doesn't match any digest algorithm
	 */
	public static DigestAlgorithm forOID(final String oid) throws DSSException {
		final DigestAlgorithm algorithm = Registry.OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * Returns the digest algorithm associated to the given XML url.
	 *
	 * @param xmlName
	 *            the algorithm uri
	 * @return the digest algorithm linked to the given uri
	 * @throws DSSException
	 *             if the uri doesn't match any digest algorithm
	 */
	public static DigestAlgorithm forXML(final String xmlName) throws DSSException {
		final DigestAlgorithm algorithm = Registry.XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + xmlName);
		}
		return algorithm;
	}

	/**
	 * Returns the digest algorithm associated to the given XML url or the default one if the algorithm does not exist.
	 *
	 * @param xmlName
	 *            The XML representation of the digest algorithm
	 * @param defaultValue
	 *            The default value for the {@code DigestAlgorithm}
	 * @return the corresponding {@code DigestAlgorithm} or the default value
	 */
	public static DigestAlgorithm forXML(final String xmlName, final DigestAlgorithm defaultValue) {
		final DigestAlgorithm algorithm = Registry.XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			return defaultValue;
		}
		return algorithm;
	}

	private DigestAlgorithm(final String name, final String javaName, final String oid, final String xmlId) {
		this(name, javaName, oid, xmlId, 0);
	}

	private DigestAlgorithm(final String name, final String javaName, final String oid, final String xmlId, final int saltLength) {
		this.name = name;
		this.javaName = javaName;
		this.oid = oid;
		this.xmlId = xmlId;
		this.saltLength = saltLength;
	}

	/**
	 * Get the algorithm name
	 * 
	 * @return the algorithm name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the JCE algorithm name
	 * 
	 * @return the java algorithm name
	 */
	public String getJavaName() {
		return javaName;
	}

	/**
	 * Get the algorithm OID
	 * 
	 * @return the ASN1 algorithm OID
	 */
	public String getOid() {
		return oid;
	}

	/**
	 * Get the algorithm uri
	 * 
	 * @return the algorithm uri
	 */
	public String getXmlId() {
		return xmlId;
	}

	public int getSaltLength() {
		return saltLength;
	}

}
