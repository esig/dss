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
import java.util.Map.Entry;

/**
 * Supported signature algorithms.
 *
 */
public enum SignatureAlgorithm {

	RSA_SHA1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA1),

	RSA_SHA224(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA224),

	RSA_SHA256(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA256),

	RSA_SHA384(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA384),

	RSA_SHA512(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA512),

	RSA_SHA3_224(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_224),

	RSA_SHA3_256(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_256),

	RSA_SHA3_384(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_384),

	RSA_SHA3_512(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_512),

	RSA_SSA_PSS_SHA1_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA1, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA224_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA224, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA256_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA256, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA384_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA384, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA512_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA512, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA3_224_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_224, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA3_256_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_256, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA3_384_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_384, MaskGenerationFunction.MGF1),

	RSA_SSA_PSS_SHA3_512_MGF1(EncryptionAlgorithm.RSA, DigestAlgorithm.SHA3_512, MaskGenerationFunction.MGF1),

	RSA_RIPEMD160(EncryptionAlgorithm.RSA, DigestAlgorithm.RIPEMD160),

	RSA_MD5(EncryptionAlgorithm.RSA, DigestAlgorithm.MD5),

	RSA_MD2(EncryptionAlgorithm.RSA, DigestAlgorithm.MD2),

	ECDSA_SHA1(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA1),

	ECDSA_SHA224(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA224),

	ECDSA_SHA256(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA256),

	ECDSA_SHA384(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA384),

	ECDSA_SHA512(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA512),

	ECDSA_SHA3_224(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_224),

	ECDSA_SHA3_256(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_256),

	ECDSA_SHA3_384(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_384),

	ECDSA_SHA3_512(EncryptionAlgorithm.ECDSA, DigestAlgorithm.SHA3_512),

	ECDSA_RIPEMD160(EncryptionAlgorithm.ECDSA, DigestAlgorithm.RIPEMD160),

	DSA_SHA1(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA1),

	DSA_SHA224(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA224),

	DSA_SHA256(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA256),

	DSA_SHA384(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA384),

	DSA_SHA512(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA512),

	DSA_SHA3_224(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_224),

	DSA_SHA3_256(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_256),

	DSA_SHA3_384(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_384),

	DSA_SHA3_512(EncryptionAlgorithm.DSA, DigestAlgorithm.SHA3_512),

	HMAC_SHA1(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA1),

	HMAC_SHA224(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA224),

	HMAC_SHA256(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA256),

	HMAC_SHA384(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA384),

	HMAC_SHA512(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA512),

	HMAC_SHA3_224(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_224),

	HMAC_SHA3_256(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_256),

	HMAC_SHA3_384(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_384),

	HMAC_SHA3_512(EncryptionAlgorithm.HMAC, DigestAlgorithm.SHA3_512),

	HMAC_RIPEMD160(EncryptionAlgorithm.HMAC, DigestAlgorithm.RIPEMD160);

	private final EncryptionAlgorithm encryptionAlgo;

	private final DigestAlgorithm digestAlgo;

	private final MaskGenerationFunction maskGenerationFunction;

	// http://www.w3.org/TR/2013/NOTE-xmlsec-algorithms-20130411/
	private static final Map<String, SignatureAlgorithm> XML_ALGORITHMS = registerXmlAlgorithms();

	private static final Map<SignatureAlgorithm, String> XML_ALGORITHMS_FOR_KEY = registerXmlAlgorithmsForKey();

	private static Map<String, SignatureAlgorithm> registerXmlAlgorithms() {

		Map<String, SignatureAlgorithm> xmlAlgorithms = new HashMap<String, SignatureAlgorithm>();
		xmlAlgorithms.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", RSA_SHA1);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", RSA_SHA224);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", RSA_SHA256);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", RSA_SHA384);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", RSA_SHA512);

		// https://tools.ietf.org/html/rfc6931#section-2.3.10
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1", RSA_SSA_PSS_SHA1_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha224-rsa-MGF1", RSA_SSA_PSS_SHA224_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1", RSA_SSA_PSS_SHA256_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1", RSA_SSA_PSS_SHA384_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1", RSA_SSA_PSS_SHA512_MGF1);

		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha3-224-rsa-MGF1", RSA_SSA_PSS_SHA3_224_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha3-256-rsa-MGF1", RSA_SSA_PSS_SHA3_256_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha3-384-rsa-MGF1", RSA_SSA_PSS_SHA3_384_MGF1);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#sha3-512-rsa-MGF1", RSA_SSA_PSS_SHA3_512_MGF1);

		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160", RSA_RIPEMD160);
		// Support of not standard AT algorithm name
		// http://www.rfc-editor.org/rfc/rfc4051.txt --> http://www.rfc-editor.org/errata_search.php?rfc=4051
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more/rsa-ripemd160", RSA_RIPEMD160);

		// Following algorithms are not in ETSI TS 102 176-1 V2.0.0:
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", RSA_MD5);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-md2", RSA_MD2);
		// Following end.
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", ECDSA_SHA1);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224", ECDSA_SHA224);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", ECDSA_SHA256);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", ECDSA_SHA384);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", ECDSA_SHA512);
		xmlAlgorithms.put("http://www.w3.org/2007/05/xmldsig-more#ecdsa-ripemd160", ECDSA_RIPEMD160);

		xmlAlgorithms.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", DSA_SHA1);
		xmlAlgorithms.put("http://www.w3.org/2009/xmldsig11#dsa-sha256", DSA_SHA256);
		// Following algorithms are not in ETSI TS 102 176-1 V2.0.0:
		xmlAlgorithms.put("http://www.w3.org/2000/09/xmldsig#hmac-sha1", HMAC_SHA1);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha224", HMAC_SHA224);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", HMAC_SHA256);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", HMAC_SHA384);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", HMAC_SHA512);
		xmlAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", HMAC_RIPEMD160);
		// Following end.
		return xmlAlgorithms;
	}

	private static Map<SignatureAlgorithm, String> registerXmlAlgorithmsForKey() {

		Map<SignatureAlgorithm, String> xmlAlgorithms = new HashMap<SignatureAlgorithm, String>();
		for (Entry<String, SignatureAlgorithm> entry : XML_ALGORITHMS.entrySet()) {

			xmlAlgorithms.put(entry.getValue(), entry.getKey());
		}
		return xmlAlgorithms;
	}

	private static final Map<String, SignatureAlgorithm> OID_ALGORITHMS = registerOIDAlgorithms();

	private static Map<String, SignatureAlgorithm> registerOIDAlgorithms() {

		Map<String, SignatureAlgorithm> oidAlgorithms = new HashMap<String, SignatureAlgorithm>();

		oidAlgorithms.put("1.2.840.113549.1.1.5", RSA_SHA1);
		oidAlgorithms.put("1.3.14.3.2.29", RSA_SHA1);
		oidAlgorithms.put("1.2.840.113549.1.1.14", RSA_SHA224);
		oidAlgorithms.put("1.2.840.113549.1.1.11", RSA_SHA256);
		oidAlgorithms.put("1.2.840.113549.1.1.12", RSA_SHA384);
		oidAlgorithms.put("1.2.840.113549.1.1.13", RSA_SHA512);
		oidAlgorithms.put("1.3.36.3.3.1.2", RSA_RIPEMD160);

		oidAlgorithms.put("2.16.840.1.101.3.4.3.13", RSA_SHA3_224);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.14", RSA_SHA3_256);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.15", RSA_SHA3_384);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.16", RSA_SHA3_512);

		oidAlgorithms.put("1.2.840.113549.1.1.4", RSA_MD5);
		oidAlgorithms.put("1.2.840.113549.1.1.2", RSA_MD2);
		/**
		 * RFC 2313:<br>
		 * "md2WithRSAEncryption", 1.2.840.113549.1.1.2<br>
		 * "md4WithRSAEncryption", 1.2.840.113549.1.1.3<br>
		 * "md5WithRSAEncryption", 1.2.840.113549.1.1.4<br>
		 */

		oidAlgorithms.put("1.2.840.10045.4.1", ECDSA_SHA1);
		oidAlgorithms.put("1.2.840.10045.4.3.1", ECDSA_SHA224);
		oidAlgorithms.put("1.2.840.10045.4.3.2", ECDSA_SHA256);
		oidAlgorithms.put("1.2.840.10045.4.3.3", ECDSA_SHA384);
		oidAlgorithms.put("1.2.840.10045.4.3.4", ECDSA_SHA512);
		oidAlgorithms.put("0.4.0.127.0.7.1.1.4.1.6", ECDSA_RIPEMD160);

		/*
		 * id-ecdsa-with-sha3-256 {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3)
		 * nistAlgorithm(4) sigAlgs(3) 10}
		 * NIST CSOR [18]
		 * id-ecdsa-with-sha3-384 {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3)
		 * nistAlgorithm(4) sigAlgs(3) 11}
		 * NIST CSOR [18]
		 * id-ecdsa-with-sha3-512 {joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3)
		 * nistAlgorithm(4) sigAlgs(3) 12}
		 */
		oidAlgorithms.put("2.16.840.1.101.3.4.3.9", ECDSA_SHA3_224);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.10", ECDSA_SHA3_256);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.11", ECDSA_SHA3_384);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.12", ECDSA_SHA3_512);

		oidAlgorithms.put("1.2.840.10040.4.3", DSA_SHA1);
		oidAlgorithms.put("1.2.14888.3.0.1", DSA_SHA1);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.1", DSA_SHA224);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.2", DSA_SHA256);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.3", DSA_SHA384);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.4", DSA_SHA512);

		oidAlgorithms.put("2.16.840.1.101.3.4.3.5", DSA_SHA3_224);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.6", DSA_SHA3_256);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.7", DSA_SHA3_384);
		oidAlgorithms.put("2.16.840.1.101.3.4.3.8", DSA_SHA3_512);

		oidAlgorithms.put("1.2.840.113549.2.7", HMAC_SHA1);
		oidAlgorithms.put("1.2.840.113549.2.8", HMAC_SHA224);
		oidAlgorithms.put("1.2.840.113549.2.9", HMAC_SHA256);
		oidAlgorithms.put("1.2.840.113549.2.10", HMAC_SHA384);
		oidAlgorithms.put("1.2.840.113549.2.11", HMAC_SHA512);
		oidAlgorithms.put("1.3.6.1.5.5.8.1.4", HMAC_RIPEMD160);

		oidAlgorithms.put("2.16.840.1.101.3.4.2.13", HMAC_SHA3_224);
		oidAlgorithms.put("2.16.840.1.101.3.4.2.14", HMAC_SHA3_256);
		oidAlgorithms.put("2.16.840.1.101.3.4.2.15", HMAC_SHA3_384);
		oidAlgorithms.put("2.16.840.1.101.3.4.2.16", HMAC_SHA3_512);

		oidAlgorithms.put("1.2.840.113549.1.1.10", RSA_SSA_PSS_SHA1_MGF1);

		return oidAlgorithms;
	}

	private static final Map<String, SignatureAlgorithm> JAVA_ALGORITHMS = registerJavaAlgorithms();

	private static final Map<SignatureAlgorithm, String> JAVA_ALGORITHMS_FOR_KEY = registerJavaAlgorithmsForKey();

	private static Map<String, SignatureAlgorithm> registerJavaAlgorithms() {

		Map<String, SignatureAlgorithm> javaAlgorithms = new HashMap<String, SignatureAlgorithm>();

		javaAlgorithms.put("SHA1withRSA", RSA_SHA1);
		javaAlgorithms.put("SHA224withRSA", RSA_SHA224);
		javaAlgorithms.put("SHA256withRSA", RSA_SHA256);
		javaAlgorithms.put("SHA384withRSA", RSA_SHA384);
		javaAlgorithms.put("SHA512withRSA", RSA_SHA512);

		javaAlgorithms.put("SHA3-224withRSA", RSA_SHA3_224);
		javaAlgorithms.put("SHA3-256withRSA", RSA_SHA3_256);
		javaAlgorithms.put("SHA3-384withRSA", RSA_SHA3_384);
		javaAlgorithms.put("SHA3-512withRSA", RSA_SHA3_512);

		javaAlgorithms.put("SHA1withRSAandMGF1", RSA_SSA_PSS_SHA1_MGF1);
		javaAlgorithms.put("SHA224withRSAandMGF1", RSA_SSA_PSS_SHA224_MGF1);
		javaAlgorithms.put("SHA256withRSAandMGF1", RSA_SSA_PSS_SHA256_MGF1);
		javaAlgorithms.put("SHA384withRSAandMGF1", RSA_SSA_PSS_SHA384_MGF1);
		javaAlgorithms.put("SHA512withRSAandMGF1", RSA_SSA_PSS_SHA512_MGF1);

		javaAlgorithms.put("SHA3-224withRSAandMGF1", RSA_SSA_PSS_SHA3_224_MGF1);
		javaAlgorithms.put("SHA3-256withRSAandMGF1", RSA_SSA_PSS_SHA3_256_MGF1);
		javaAlgorithms.put("SHA3-384withRSAandMGF1", RSA_SSA_PSS_SHA3_384_MGF1);
		javaAlgorithms.put("SHA3-512withRSAandMGF1", RSA_SSA_PSS_SHA3_512_MGF1);

		javaAlgorithms.put("RIPEMD160withRSA", RSA_RIPEMD160);

		javaAlgorithms.put("MD5withRSA", RSA_MD5);
		javaAlgorithms.put("MD2withRSA", RSA_MD2);

		javaAlgorithms.put("SHA1withECDSA", ECDSA_SHA1);
		javaAlgorithms.put("SHA224withECDSA", ECDSA_SHA224);
		javaAlgorithms.put("SHA256withECDSA", ECDSA_SHA256);
		javaAlgorithms.put("SHA384withECDSA", ECDSA_SHA384);
		javaAlgorithms.put("SHA512withECDSA", ECDSA_SHA512);
		javaAlgorithms.put("RIPEMD160withECDSA", ECDSA_RIPEMD160);

		javaAlgorithms.put("SHA3-224withECDSA", ECDSA_SHA3_224);
		javaAlgorithms.put("SHA3-256withECDSA", ECDSA_SHA3_256);
		javaAlgorithms.put("SHA3-384withECDSA", ECDSA_SHA3_384);
		javaAlgorithms.put("SHA3-512withECDSA", ECDSA_SHA3_512);

		javaAlgorithms.put("SHA1withDSA", DSA_SHA1);
		javaAlgorithms.put("SHA224withDSA", DSA_SHA224);
		javaAlgorithms.put("SHA256withDSA", DSA_SHA256);
		javaAlgorithms.put("SHA384withDSA", DSA_SHA384);
		javaAlgorithms.put("SHA512withDSA", DSA_SHA512);

		javaAlgorithms.put("SHA3-224withDSA", DSA_SHA3_224);
		javaAlgorithms.put("SHA3-256withDSA", DSA_SHA3_256);
		javaAlgorithms.put("SHA3-384withDSA", DSA_SHA3_384);
		javaAlgorithms.put("SHA3-512withDSA", DSA_SHA3_512);

		javaAlgorithms.put("SHA1withHMAC", HMAC_SHA1);
		javaAlgorithms.put("SHA224withHMAC", HMAC_SHA224);
		javaAlgorithms.put("SHA256withHMAC", HMAC_SHA256);
		javaAlgorithms.put("SHA384withHMAC", HMAC_SHA384);
		javaAlgorithms.put("SHA512withHMAC", HMAC_SHA512);

		javaAlgorithms.put("SHA3-224withHMAC", HMAC_SHA3_224);
		javaAlgorithms.put("SHA3-256withHMAC", HMAC_SHA3_256);
		javaAlgorithms.put("SHA3-384withHMAC", HMAC_SHA3_384);
		javaAlgorithms.put("SHA3-512withHMAC", HMAC_SHA3_512);

		javaAlgorithms.put("RIPEMD160withHMAC", HMAC_RIPEMD160);
		return javaAlgorithms;
	}

	private static Map<SignatureAlgorithm, String> registerJavaAlgorithmsForKey() {
		final Map<SignatureAlgorithm, String> javaAlgorithms = new HashMap<SignatureAlgorithm, String>();
		for (Entry<String, SignatureAlgorithm> entry : JAVA_ALGORITHMS.entrySet()) {
			javaAlgorithms.put(entry.getValue(), entry.getKey());
		}
		return javaAlgorithms;
	}

	public static SignatureAlgorithm forXML(final String xmlName) {
		final SignatureAlgorithm algorithm = XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + xmlName);
		}
		return algorithm;
	}

	/**
	 * This method return the {@code SignatureAlgorithm} or the default value if the algorithm is unknown.
	 *
	 * @param xmlName
	 *            XML URI of the given algorithm
	 * @param defaultValue
	 *            the default value to be returned if not found
	 * @return {@code SignatureAlgorithm} or default value
	 */
	public static SignatureAlgorithm forXML(final String xmlName, final SignatureAlgorithm defaultValue) {
		final SignatureAlgorithm algorithm = XML_ALGORITHMS.get(xmlName);
		if (algorithm == null) {
			return defaultValue;
		}
		return algorithm;
	}

	public static SignatureAlgorithm forOID(final String oid) {
		final SignatureAlgorithm algorithm = OID_ALGORITHMS.get(oid);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + oid);
		}
		return algorithm;
	}

	/**
	 * For given signature algorithm and digest algorithm this function returns the Java form of the signature algorithm
	 * Signature Algorithms
	 *
	 * The algorithm names in this section can be specified when generating an instance of Signature.
	 *
	 * NONEwithRSA - The RSA signature algorithm which does not use a digesting algorithm (e.g. MD5/SHA1) before
	 * performing the RSA operation. For more information about the RSA
	 * Signature algorithms, please see PKCS1.
	 *
	 * MD2withRSA MD5withRSA - The MD2/MD5 with RSA Encryption signature algorithm which uses the MD2/MD5 digest
	 * algorithm and RSA to create and verify RSA digital signatures as
	 * defined in PKCS1.
	 *
	 * SHA1withRSA SHA256withRSA SHA384withRSA SHA512withRSA - The signature algorithm with SHA-* and the RSA encryption
	 * algorithm as defined in the OSI Interoperability Workshop,
	 * using the padding conventions described in PKCS1.
	 *
	 * NONEwithDSA - The Digital Signature Algorithm as defined in FIPS PUB 186-2. The data must be exactly 20 bytes in
	 * length. This algorithms is also known under the alias name
	 * of rawDSA.
	 *
	 * SHA1withDSA - The DSA with SHA-1 signature algorithm which uses the SHA-1 digest algorithm and DSA to create and
	 * verify DSA digital signatures as defined in FIPS PUB 186.
	 *
	 * NONEwithECDSA SHA1withECDSA SHA256withECDSA SHA384withECDSA SHA512withECDSA (ECDSA) - The ECDSA signature
	 * algorithms as defined in ANSI X9.62. Note:"ECDSA" is an ambiguous
	 * name for the "SHA1withECDSA" algorithm and should not be used. The formal name "SHA1withECDSA" should be used
	 * instead.
	 *
	 * {@code <digest>with<encryption>} - Use this to form a name for a signature algorithm with a particular message
	 * digest
	 * (such as MD2 or MD5) and algorithm (such as RSA or DSA), just
	 * as was done for the explicitly-defined standard names in this section (MD2withRSA, etc.). For the new signature
	 * schemes defined in PKCS1 v 2.0, for which the
	 * {@code <digest>with<encryption>} form is insufficient, {@code <digest>with<encryption>and<mgf>} can be used to
	 * form a name. Here,
	 * {@code <mgf>} should be replaced by a mask generation function
	 * such as MGF1. Example: MD5withRSAandMGF1.
	 *
	 * @param javaName
	 *            the java name
	 * @return the corresponding SignatureAlgorithm
	 */
	public static SignatureAlgorithm forJAVA(final String javaName) {
		final SignatureAlgorithm algorithm = JAVA_ALGORITHMS.get(javaName);
		if (algorithm == null) {
			throw new DSSException("Unsupported algorithm: " + javaName);
		}
		return algorithm;
	}

	/**
	 * For given encryption algorithm and digest algorithm this function returns the signature algorithm.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @return the corresponding combination of both algorithms
	 */
	public static SignatureAlgorithm getAlgorithm(final EncryptionAlgorithm encryptionAlgorithm, final DigestAlgorithm digestAlgorithm) {
		return getAlgorithm(encryptionAlgorithm, digestAlgorithm, null);
	}

	/**
	 * For given encryption algorithm and digest algorithm this function returns the signature algorithm.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @param mgf
	 *            the mask generation function
	 * @return the corresponding combination of both algorithms
	 */
	public static SignatureAlgorithm getAlgorithm(final EncryptionAlgorithm encryptionAlgorithm, final DigestAlgorithm digestAlgorithm,
			final MaskGenerationFunction mgf) {

		StringBuilder sb = new StringBuilder();
		sb.append(digestAlgorithm.getName());
		sb.append("with");
		sb.append(encryptionAlgorithm.getName());
		if (mgf != null) {
			sb.append("andMGF1");
		}
		return JAVA_ALGORITHMS.get(sb.toString());
	}

	/**
	 * The default constructor.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 */
	private SignatureAlgorithm(final EncryptionAlgorithm encryptionAlgorithm, final DigestAlgorithm digestAlgorithm) {
		this.encryptionAlgo = encryptionAlgorithm;
		this.digestAlgo = digestAlgorithm;
		this.maskGenerationFunction = null;
	}

	/**
	 * The default constructor.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm
	 * @param digestAlgorithm
	 *            the digest algorithm
	 * @param mgf
	 *            the mask generation function
	 */
	private SignatureAlgorithm(final EncryptionAlgorithm encryptionAlgorithm, final DigestAlgorithm digestAlgorithm,
			final MaskGenerationFunction maskGenerationFunction) {
		this.encryptionAlgo = encryptionAlgorithm;
		this.digestAlgo = digestAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
	}

	/**
	 * This method returns the encryption algorithm.
	 *
	 * @return the encryption algorithm
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgo;
	}

	/**
	 * This method returns the digest algorithm.
	 *
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgo;
	}

	/**
	 * This method returns the mask generation function.
	 *
	 * @return the mask generation function
	 */
	public MaskGenerationFunction getMaskGenerationFunction() {
		return maskGenerationFunction;
	}

	/**
	 * Returns the XML ID of the signature algorithm.
	 *
	 * @return the XML URI for the current signature algorithm.
	 */
	public String getXMLId() {
		return XML_ALGORITHMS_FOR_KEY.get(this);
	}

	/**
	 * Returns algorithm identifier corresponding to JAVA JCE class names.
	 *
	 * @return the java name for the current signature algorithm.
	 */
	public String getJCEId() {
		return JAVA_ALGORITHMS_FOR_KEY.get(this);
	}

}
