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
package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.jades.validation.EtsiUComponent;
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jades.validation.JAdESEtsiUHeader;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.jades.JAdESUtils;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.jose4j.base64url.Base64Url;
import org.jose4j.json.JsonUtil;
import org.jose4j.json.internal.json_simple.JSONArray;
import org.jose4j.json.internal.json_simple.JSONValue;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.ADO_TST;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_D;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PID;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PL;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_T;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_X5T_S;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_ATS;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_CMS;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.X5T_O;
import static org.jose4j.jwx.HeaderParameterNames.AGREEMENT_PARTY_U_INFO;
import static org.jose4j.jwx.HeaderParameterNames.AGREEMENT_PARTY_V_INFO;
import static org.jose4j.jwx.HeaderParameterNames.ALGORITHM;
import static org.jose4j.jwx.HeaderParameterNames.AUTHENTICATION_TAG;
import static org.jose4j.jwx.HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD;
import static org.jose4j.jwx.HeaderParameterNames.CONTENT_TYPE;
import static org.jose4j.jwx.HeaderParameterNames.CRITICAL;
import static org.jose4j.jwx.HeaderParameterNames.ENCRYPTION_METHOD;
import static org.jose4j.jwx.HeaderParameterNames.EPHEMERAL_PUBLIC_KEY;
import static org.jose4j.jwx.HeaderParameterNames.INITIALIZATION_VECTOR;
import static org.jose4j.jwx.HeaderParameterNames.JWK;
import static org.jose4j.jwx.HeaderParameterNames.JWK_SET_URL;
import static org.jose4j.jwx.HeaderParameterNames.KEY_ID;
import static org.jose4j.jwx.HeaderParameterNames.PBES2_ITERATION_COUNT;
import static org.jose4j.jwx.HeaderParameterNames.PBES2_SALT_INPUT;
import static org.jose4j.jwx.HeaderParameterNames.TYPE;
import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_CHAIN;
import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_SHA256_THUMBPRINT;
import static org.jose4j.jwx.HeaderParameterNames.X509_CERTIFICATE_THUMBPRINT;
import static org.jose4j.jwx.HeaderParameterNames.X509_URL;
import static org.jose4j.jwx.HeaderParameterNames.ZIP;

/**
 * Utility class for working with JSON objects
 *
 */
public class DSSJsonUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSJsonUtils.class);

	/** The MimeType application prefix */
	public static final String MIME_TYPE_APPLICATION_PREFIX = "application/";

	/** The HttpHeader defining the Digest value of a signed message body */
	public static final String HTTP_HEADER_DIGEST = "Digest";

	/** The binary content encoding (RFC 2045) */
	public static final String CONTENT_ENCODING_BINARY = "binary";

	/** Format date-time as specified in RFC 3339 5.6 */
	private static final String DATE_TIME_FORMAT_RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
	
	/**
	 * Copied from org.jose4j.base64url.internal.apache.commons.codec.binary.Base64
	 * 
     * This is a copy of the STANDARD_ENCODE_TABLE above, but with + and /
     * changed to - and _ to make the encoded Base64 results more URL-SAFE.
     * This table is only used when the Base64's mode is set to URL-SAFE.
     */
    private static final byte[] URL_SAFE_ENCODE_TABLE = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };
	
	/**
	 * Contains protected header names that are supported and can be present in the critical ('crit') attribute
	 */
	private static final Set<String> protectedCriticalHeaders;
	
	/**
	 * Contains a list of headers that MUST NOT be incorporated into a 'crit' header (includes RFC 7515, RFC 7518) 
	 */
	private static final Set<String> criticalHeaderExceptions;
	
	static {
		protectedCriticalHeaders = Stream.of(
				/* JAdES EN 119-812 constraints */
				SIG_T, X5T_O, SIG_X5T_S, SR_CMS, SIG_PL, SR_ATS, ADO_TST, SIG_PID, SIG_D,
				/* RFC7797 'b64' */
				BASE64URL_ENCODE_PAYLOAD ).collect(Collectors.toSet());
		
		criticalHeaderExceptions = Stream.of(
				/* RFC 7515 */
				ALGORITHM, JWK_SET_URL, JWK, KEY_ID, X509_URL, X509_CERTIFICATE_CHAIN, X509_CERTIFICATE_THUMBPRINT,
				X509_CERTIFICATE_SHA256_THUMBPRINT, TYPE, CONTENT_TYPE, CRITICAL,
				/* RFC 7518 */
				EPHEMERAL_PUBLIC_KEY, AGREEMENT_PARTY_U_INFO, AGREEMENT_PARTY_V_INFO, INITIALIZATION_VECTOR, AUTHENTICATION_TAG, 
				PBES2_SALT_INPUT, PBES2_ITERATION_COUNT, ENCRYPTION_METHOD, ZIP ).collect(Collectors.toSet());
	}
	
	private DSSJsonUtils() {
		// empty
	}
	
	/**
	 * Returns ASCII-encoded array
	 * 
	 * @param str {@link String} to encode to ASCII
	 * @return byte array
	 */
	public static byte[] getAsciiBytes(String str) {
		return StringUtil.getBytesAscii(str);
	}
	
	/**
	 * Returns a base64Url encoded string
	 * 
	 * @param binary a byte array to encode
	 * @return base64Url encoded {@link String}
	 */
	public static String toBase64Url(byte[] binary) {
		return Base64Url.encode(binary);
	}

	/**
	 * Returns a base64Url encoded string
	 * 
	 * @param document {@link DSSDocument} to encode
	 * @return base64Url encoded {@link String}
	 */
	public static String toBase64Url(DSSDocument document) {
		return toBase64Url(DSSUtils.toByteArray(document));
	}

	/**
	 * Returns a base64Url encoded string from the provided JSON Object or JSON
	 * Array
	 * 
	 * @param object JSON Object or JSON Array to encode
	 * @return base64Url encoded {@link String}
	 */
	public static String toBase64Url(Object object) {
		String json = JSONValue.toJSONString(object);
		return Base64Url.encode(json.getBytes());
	}
	
	/**
	 * Returns the decoded binary for a base64url encoded string
	 * 
	 * @param base64UrlEncoded the String to be decoded
	 * @return the decoded binary
	 */
	public static byte[] fromBase64Url(String base64UrlEncoded) {
		return Base64Url.decode(base64UrlEncoded);
	}
	
	/**
	 * Checks if the provided string is base64Url encoded
	 * 
	 * @param str {@link String} to check
	 * @return TRUE if the String is base64Url encoded, FALSE otherwise
	 */
	public static boolean isBase64UrlEncoded(String str) {
		try {
			Base64Url.decode(str);
			for (byte b : str.getBytes()) {
				if (!isBase64UrlEncoded(b)) {
					return false;
				}
			}
			return true;
		} catch (Exception e) {
			return false;
		}
	}
	
	/**
	 * Checks if the byte is Base64Url encoded
	 * 
	 * @param b a byte to check
	 * @return TRUE if the byte is Base64Url encoded, FALSE otherwise
	 */
	public static boolean isBase64UrlEncoded(byte b) {
		for (byte m : URL_SAFE_ENCODE_TABLE) {
			if (b == m) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if the payload is JWS URL safe See RFC 7797 : 5.2. Unencoded JWS
	 * Compact Serialization Payload
	 * 
	 * @param payloadString {@link String} representing a payload
	 * @return TRUE if the payload is URL safe, FALSE otherwise
	 */
	public static boolean isUrlSafePayload(String payloadString) {
		/*
		 * When using the JWS Compact Serialization, unencoded non-detached
		 * payloads using period ('.') characters would cause parsing errors;
		 * such payloads MUST NOT be used with the JWS Compact Serialization.
		 * ...
		 * The ASCII space character and all printable ASCII characters
		 * other than period ('.') (those characters in the ranges %x20-2D and
		 * %x2F-7E) MAY be included in a non-detached payload using the JWS
		 * Compact Serialization, provided that the application can transmit the
		 * resulting JWS without modification.
		 */
		return payloadString.matches("[^\\P{Print}.]*");
	}
	
	/**
	 * Checks if the given byte is url safe
	 * See RFC 7797 : 5.2. Unencoded JWS Compact Serialization Payload
	 * 
	 * @param b a byte to check
	 * @return TRUE if the byte is url-safe, FALSE otherwise
	 */
	public static boolean isUrlSafe(byte b) {
		return 0x1f < b && b < 0x2e || 0x2e < b && b < 0x7f;
	}

	/**
	 * Checks if the binaries contain a UTF-8 encoded string
	 *
	 * @param binaries byte array to check
	 * @return TRUE if binaries contain a UTF-8 encoded string, FALSE otherwise
	 */
	public static boolean isUtf8(byte[] binaries) {
		try {
			CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
			ByteBuffer buf = ByteBuffer.wrap(binaries);
			decoder.decode(buf);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Concatenates the given strings with a '.' (dot) between.
	 * 
	 * Example: "xxx", "yyy", "zzz" to "xxx.yyy.zzz"
	 * 
	 * @param strings a list of {@link String}s to concatenate
	 * @return a concatenation string result
	 */
	public static String concatenate(String... strings) {
		return CompactSerializer.serialize(strings);
	}
	
	/**
	 * Returns set of supported protected critical headers
	 * 
	 * @return set of supported protected critical header strings
	 */
	public static Set<String> getSupportedProtectedCriticalHeaders() {
		return protectedCriticalHeaders;
	}

	/**
	 * Checks if the given {@code headerName} is a critical header exception
	 * (shall not be incorporated within 'crit' header). See RFC 7515
	 *
	 * @param headerName {@link String} header name to check
	 * @return TRUE if the header is critical header exception, FALSE otherwise
	 */
	public static boolean isCriticalHeaderException(String headerName) {
		return criticalHeaderExceptions.contains(headerName);
	}
	
	/**
	 * Creates a {@link Digest} object from a JSON structure
	 * 
	 * @param digestValueAndAlgo a Map with digAlg and digVal values
	 * @return an instance of Digest or null
	 */
	public static Digest getDigest(Map<?, ?> digestValueAndAlgo) {
		try {
			if (Utils.isMapNotEmpty(digestValueAndAlgo)) {
				String digestAlgoURI = getAsString(digestValueAndAlgo, JAdESHeaderParameterNames.DIG_ALG);
				String digestValueBase64 = getAsString(digestValueAndAlgo, JAdESHeaderParameterNames.DIG_VAL);
				if (Utils.isStringNotEmpty(digestAlgoURI) && Utils.isStringNotEmpty(digestValueBase64)) {
					return new Digest(DigestAlgorithm.forJAdES(digestAlgoURI),
							DSSJsonUtils.fromBase64Url(digestValueBase64));
				}
			}

		} catch (Exception e) {
			LOG.warn("Unable to extract Digest Algorithm and Value. Reason : {}", e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Creates an 'oid' LinkedJSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param objectIdentifier {@link ObjectIdentifier} to create an 'oid' from
	 * @return 'oid' {@link JsonObject}
	 */
	public static JsonObject getOidObject(ObjectIdentifier objectIdentifier) {
		return getOidObject(getUriOrUrnOid(objectIdentifier), objectIdentifier.getDescription(),
				objectIdentifier.getDocumentationReferences());
	}

	/**
	 * Returns URI if present, otherwise URN encoded OID (see RFC 3061)
	 * Returns NULL if non of them is present
	 *
	 * @param objectIdentifier {@link ObjectIdentifier} used to build an object of 'oid' type
	 * @return {@link String} URI
	 */
	public static String getUriOrUrnOid(ObjectIdentifier objectIdentifier) {
		/*
		 * TS 119 182-1 : 5.4.1 The oId data type
		 * If both an OID and a URI exist identifying one object, the URI value should be used in the id member.
		 */
		String uri = objectIdentifier.getUri();
		if (uri == null && objectIdentifier.getOid() != null) {
			uri = DSSUtils.toUrnOid(objectIdentifier.getOid());
		}
		return uri;
	}

	/**
	 * Creates an 'oid' JsonObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param uri {@link String} URI defining the object. The property is REQUIRED.
	 * @param desc {@link String} the object description. The property is OPTIONAL.
	 * @param docRefs an array of {@link String} URIs containing any other additional information about the object. 
	 * 				The property is OPTIONAL.
	 * @return 'oid' {@link JsonObject}
	 */
	public static JsonObject getOidObject(String uri, String desc, String[] docRefs) {
		Objects.requireNonNull(uri, "uri must be defined!");
		
		Map<String, Object> oidParams = new LinkedHashMap<>();
		oidParams.put(JAdESHeaderParameterNames.ID, uri);
		if (Utils.isStringNotEmpty(desc)) {
			oidParams.put(JAdESHeaderParameterNames.DESC, desc);
		}
		if (Utils.isArrayNotEmpty(docRefs)) {
			oidParams.put(JAdESHeaderParameterNames.DOC_REFS, new JSONArray(Arrays.asList(docRefs)));
		}
		
		return new JsonObject(oidParams);
	}
	
	/**
	 * Creates a 'tstContainer' JsonObject according to EN 119-182 ch. 5.4.3.3 The tstContainer type
	 * 
	 * @param timestampBinaries a list of {@link TimestampBinary}s to incorporate
	 * @param canonicalizationMethodUri a canonicalization method (OPTIONAL, e.g. shall not be present for content timestamps)
	 * @return 'tstContainer' {@link JsonObject}
	 */
	public static JsonObject getTstContainer(List<TimestampBinary> timestampBinaries, String canonicalizationMethodUri) {
		if (Utils.isCollectionEmpty(timestampBinaries)) {
			throw new IllegalArgumentException("Impossible to create 'tstContainer'. List of TimestampBinaries cannot be null or empty!");
		}

		Map<String, Object> tstContainerParams = new LinkedHashMap<>();
		if (canonicalizationMethodUri != null) {
			tstContainerParams.put(JAdESHeaderParameterNames.CANON_ALG, canonicalizationMethodUri);
		}
		List<JsonObject> tsTokens = new ArrayList<>();
		for (TimestampBinary timestampBinary : timestampBinaries) {
			JsonObject tstToken = getTstToken(timestampBinary);
			tsTokens.add(tstToken);
		}
		JSONArray tsTokensArray = new JSONArray(tsTokens);
		tstContainerParams.put(JAdESHeaderParameterNames.TST_TOKENS, tsTokensArray);
		
		return new JsonObject(tstContainerParams);
	}
	
	/**
	 * Creates a 'tstToken' JsonObject according to EN 119-182 ch. 5.4.3.3 The tstContainer type
	 * 
	 * @param timestampBinary {@link TimestampBinary}s to incorporate
	 * @return 'tstToken' {@link JsonObject}
	 */
	private static JsonObject getTstToken(TimestampBinary timestampBinary) {
		Objects.requireNonNull(timestampBinary, "timestampBinary cannot be null!");
		
		Map<String, Object> tstTokenParams = new HashMap<>();
		// only RFC 3161 TimestampTokens are supported
		// 'type', 'encoding' and 'specRef' params are not need to be defined (see EN 119-182 ch. 5.4.3.3)
		tstTokenParams.put(JAdESHeaderParameterNames.VAL, Utils.toBase64(timestampBinary.getBytes()));
		
		return new JsonObject(tstTokenParams);
	}
	
	/**
	 * Concatenates document octets to a single byte array
	 * 
	 * @param documents a list of {@link DSSDocument}s to concatenate
	 * @param isBase64UrlEncoded defines whether the document octets shall be base64url-encoded
	 * @return a byte array of document octets
	 */
	public static byte[] concatenateDSSDocuments(List<DSSDocument> documents, boolean isBase64UrlEncoded) {
		if (Utils.isCollectionEmpty(documents)) {
			throw new IllegalArgumentException("Unable to build a JWS Payload. Reason : the detached content is not provided!");
		}
		if (documents.size() == 1) {
			return getDocumentOctets(documents.get(0), isBase64UrlEncoded);
		}

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				baos.write(getDocumentOctets(document, isBase64UrlEncoded));
			}
			return baos.toByteArray();

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build a JWS Payload. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Writes digest on a concatenated binaries of provided {@code documents}
	 *
	 * @param documents list of {@link DSSDocument}s to be concatenated
	 * @param isBase64UrlEncoded defines whether the document octets shall be base64url-encoded
	 * @param digestCalculator {@link DSSMessageDigestCalculator} to compute message-digest with
	 */
	public static void writeDocumentsDigest(List<DSSDocument> documents, boolean isBase64UrlEncoded,
											DSSMessageDigestCalculator digestCalculator) {
		if (Utils.isCollectionEmpty(documents)) {
			throw new IllegalArgumentException("Unable to build a message-digest. Reason : the detached content is not provided!");
		}

		byte[] octets = null;
		if (documents.size() == 1) {
			octets = getDocumentOctets(documents.get(0), isBase64UrlEncoded);
			digestCalculator.update(octets);

		} else {
			for (DSSDocument document : documents) {
				octets = getDocumentOctets(document, isBase64UrlEncoded);
				digestCalculator.update(octets);
			}
		}
	}

	/**
	 * This method returns binaries of the {@code document} to be used for payload computation,
	 * depending on the {@code isBase64UrlEncoded} parameter.
	 * When {@code isBase64UrlEncoded} is set to TRUE, returns base64url-encoded binaries of the {@code document}.
	 * When {@code isBase64UrlEncoded} is set to FALSE, returns original octets of the document.
	 *
	 * @param document {@link DSSDocument} to get octets from
	 * @param isBase64UrlEncoded defines whether return base64url-encoded octets
	 * @return octets of the provided {@link DSSDocument}
	 */
	public static byte[] getDocumentOctets(DSSDocument document, boolean isBase64UrlEncoded) {
		byte[] octets = DSSUtils.toByteArray(document);
		if (isBase64UrlEncoded) {
			octets = DSSJsonUtils.toBase64Url(octets).getBytes();
		}
		return octets;
	}
	
	/**
	 * Checks if the provided document is JSON document
	 * 
	 * @param document {@link DSSDocument} to check
	 * @return TRUE of the document is JSON, FALSE otherwise
	 */
	public static boolean isJsonDocument(DSSDocument document) {
		if (isAllowedSignatureDocumentType(document)) {
			try (InputStream is = document.openStream(); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
				int firstChar = is.read();
				if (firstChar == '{') {
					baos.write(firstChar);
					Utils.copy(is, baos);
					if (baos.size() < 2) {
						return false;
					}
					Map<String, Object> json = JsonUtil.parseJson(baos.toString());
					return json != null;
				}
			} catch (JoseException e) {
				LOG.warn("Unable to parse content as JSON : {}", e.getMessage());
			} catch (IOException e) {
				throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
			}
		}
		return false;
	}

	/**
	 * Checks if the signature document has an allowed type (bytes can be extracted)
	 *
	 * @param document {@link DSSDocument} to check
	 * @return TRUE if the document is of an allowed signature type, FALSE otherwise
	 */
	public static boolean isAllowedSignatureDocumentType(DSSDocument document) {
		if (document instanceof DigestDocument || document instanceof HTTPHeader) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("The provided document of class '{}' cannot be parsed.", document.getClass());
			}
			return false;
		}
		return true;
	}

	/**
	 * This method returns the etsiU container with the unsigned properties or an
	 * empty List
	 * 
	 * @param jws the signature
	 * @return etsiU content or an empty List
	 */
	@SuppressWarnings("unchecked")
	public static List<Object> getEtsiU(JWS jws) {
		Map<String, Object> unprotected = jws.getUnprotected();
		if (unprotected == null) {
			return Collections.emptyList();
		}
		Object etsiU = unprotected.get(JAdESHeaderParameterNames.ETSI_U);
		if (!(etsiU instanceof List)) {
			LOG.warn("Unable to extract 'etsiU' header : the obtained entry is not an array!");
			return Collections.emptyList();
		}
		return (List<Object>) etsiU;
	}
	
	/**
	 * Returns a list of unsigned 'etsiU' properties matching the {@code headerName}
	 * from the {@code jws}
	 * 
	 * @param etsiUHeader {@link JAdESEtsiUHeader} to extract values from
	 * @param headerName  {@link String} name of the unsigned header
	 * @return a list of {@link EtsiUComponent}s
	 */
	public static List<EtsiUComponent> getUnsignedPropertiesWithHeaderName(JAdESEtsiUHeader etsiUHeader, String headerName) {
		if (!etsiUHeader.isExist()) {
			return Collections.emptyList();
		}
		
		List<EtsiUComponent> componentsWithHeaderName = new ArrayList<>();
		for (EtsiUComponent attribute : etsiUHeader.getAttributes()) {
			if (headerName.equals(attribute.getHeaderName())) {
				componentsWithHeaderName.add(attribute);
			}
		}
		return componentsWithHeaderName;
	}

	/**
	 * Parses a IETF RFC 3339 dateTime String
	 * 
	 * @param dateTimeString {@link String} in the RFC 3339 format to parse
	 * @return {@link Date}
	 */
	public static Date getDate(String dateTimeString) {
		if (Utils.isStringNotEmpty(dateTimeString)) {
			try {
				SimpleDateFormat sdf = new SimpleDateFormat(DATE_TIME_FORMAT_RFC3339);
				sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
				return sdf.parse(dateTimeString);
			} catch (ParseException e) {
				LOG.warn("Unable to parse date with value '{}' : {}", dateTimeString, e.getMessage());
			}
		}
		return null;
	}

	/**
	 * Parses the 'kid' header value as in IETF RFC 5035
	 * 
	 * @param value {@link String} IssuerSerial to parse
	 * @return {@link IssuerSerial}
	 */
	public static IssuerSerial getIssuerSerial(String value) {
		if (Utils.isStringNotEmpty(value) && Utils.isBase64Encoded(value)) {
			byte[] binary = Utils.fromBase64(value);
			return DSSASN1Utils.getIssuerSerial(binary);
		}
		return null;
	}

	/**
	 * Generates the 'kid' value as in IETF RFC 5035
	 * 
	 * @param signingCertificate {@link CertificateToken} representing the singing
	 *                           certificate
	 * @return {@link String} 'kid' header value
	 */
	public static String generateKid(CertificateToken signingCertificate) {
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(signingCertificate);
		return Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));
	}
	
	/**
	 * Extracts a counter signature from 'cSig' value with respect to the found format
	 * 
	 * @param cSigAttribute an attribute containing the 'cSig' element
	 * @param masterSignature {@link JAdESSignature} the master signature
	 * @return {@link JAdESSignature}
	 */
	@SuppressWarnings("unchecked")
	public static JAdESSignature extractJAdESCounterSignature(EtsiUComponent cSigAttribute, JAdESSignature masterSignature) {
		Object cSigObject = cSigAttribute.getValue();
		
		String cSigValue = null;
		if (cSigObject instanceof String) {
			cSigValue = (String) cSigObject;
			
		} else if (cSigObject instanceof Map<?, ?>) {
			Map<String, Object> cSigMap = (Map<String, Object>) cSigObject;			
			cSigValue = JsonUtil.toJson(cSigMap);
			
		} else {
			LOG.warn("Unsupported entry of type 'cSig' found! Class : {}. The entry is skipped", cSigObject.getClass());
			
		}
		
		if (Utils.isStringNotEmpty(cSigValue)) {
			InMemoryDocument cSigDocument = new InMemoryDocument(cSigValue.getBytes());
			
			JAdESDocumentValidatorFactory factory = new JAdESDocumentValidatorFactory();
			if (factory.isSupported(cSigDocument)) {
				SignedDocumentValidator validator = factory.create(cSigDocument);
				List<AdvancedSignature> signatures = validator.getSignatures();

				/*
				 * 5.3.2 The cSig (counter signature) JSON object
				 * 
				 * The cSig JSON object shall contain one counter signature of the JAdES signature where cSig is incorporated.
				 */
				if (signatures.size() == 1) {
					JAdESSignature signature = (JAdESSignature) signatures.iterator().next(); // only one is considered
					signature.setMasterSignature(masterSignature);
					signature.setMasterCSigComponent(cSigAttribute);
					signature.setDetachedContents(Arrays.asList(new InMemoryDocument(masterSignature.getSignatureValue())));
					if (LOG.isDebugEnabled()) {
						LOG.debug("A JWS counter signature found with Id : '{}'", signature.getId());
					}
					return signature;
				} else {
					LOG.warn("{} counter signatures found in 'cSig' element. Only one is allowed!", signatures.size());
				}
			}
		}
		
		return null;
	}
	
	/**
	 * Validates {@code JWS} against a JAdES schema (ETSI TS 119 182-1)
	 * 
	 * @param jws {@link JWS} to validate
	 * @return a list of {@link String}s containing validation errors, empty list if
	 *         no error occurred
	 */
	@SuppressWarnings("unchecked")
	public static List<String> validateAgainstJAdESSchema(JWS jws) {
		List<String> errors = new ArrayList<>();
		
		String headerJson = jws.getHeaders().getFullHeaderAsJsonString();
		errors.addAll(JAdESUtils.getInstance().validateAgainstJWSProtectedHeaderSchema(headerJson));
		
		Map<String, Object> unprotected = jws.getUnprotected();
		if (Utils.isMapNotEmpty(unprotected)) {
			String unprotectedJson = JsonUtil.toJson(unprotected);
			errors.addAll(JAdESUtils.getInstance().validateAgainstJWSUnprotectedHeaderSchema(unprotectedJson));

			Object etsiU = unprotected.get(JAdESHeaderParameterNames.ETSI_U);
			if (etsiU instanceof List<?>) {
				List<Object> etsiUComponents = (List<Object>) etsiU;
				if (areAllBase64UrlComponents(etsiUComponents)) {
					Map<String, Object> clearEtsiURepresentation = getClearEtsiURepresentation(unprotected);
					String clearEtsiUJson = JsonUtil.toJson(clearEtsiURepresentation);
					errors.addAll(JAdESUtils.getInstance().validateAgainstJWSUnprotectedHeaderSchema(clearEtsiUJson));
				}
			}
		}
		
		return errors;
	}

	/**
	 * Checks if all components have one type (strings or objects)
	 * 
	 * @param components a list of objects to check
	 * @return TRUE if all components are uniform (strings or objects), FALSE
	 *         otherwise
	 */
	public static boolean checkComponentsUnicity(List<Object> components) {
		if (Utils.isCollectionNotEmpty(components)) {
			Iterator<Object> iterator = components.iterator();
			Object component = iterator.next();
			boolean stringFormat = isStringFormat(component);
			while (iterator.hasNext()) {
				component = iterator.next();
				if (stringFormat != isStringFormat(component)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Checks of the object is an instance of a String class
	 * 
	 * @param object to check
	 * @return TRUE if the object is an instance of {@code String} class, FALSE
	 *         otherwise
	 */
	public static boolean isStringFormat(Object object) {
		return object instanceof String;
	}

	/**
	 * Checks if the all components are base64Url encoded
	 * 
	 * @param components a list of components to check
	 * @return TRUE if all of the components are base64Url encoded, FALSE otherwise
	 */
	public static boolean areAllBase64UrlComponents(List<Object> components) {
		if (Utils.isCollectionNotEmpty(components)) {
			for (Object component : components) {
				if (!isStringFormat(component) || !DSSJsonUtils.isBase64UrlEncoded((String) component)) {
					return false;
				}
			}
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> getClearEtsiURepresentation(Map<String, Object> unprotected) {
		List<Object> clearComponents = new ArrayList<>();
		List<Object> stringComponents = (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);
		for (Object component : stringComponents) {
			Map<String, Object> json = parseEtsiUComponent(component);
			clearComponents.add(json);
		}
		Map<String, Object> clearEtsiU = new HashMap<>();
		clearEtsiU.put(JAdESHeaderParameterNames.ETSI_U, clearComponents);
		return clearEtsiU;
	}

	/**
	 * Parses 'etsiU' component as it is (base64url-encoded or JSON), and returns the resulting Map
	 *
	 * @param etsiUComponent object to parse (base64url-encoded or JSON)
	 * @return map representing the object
	 */
	@SuppressWarnings("unchecked")
	public static Map<String, Object> parseEtsiUComponent(Object etsiUComponent) {
		try {
			if (etsiUComponent instanceof Map) {
				Map<String, Object> map = (Map<String, Object>) etsiUComponent;
				if (map.size() != 1) {
					LOG.warn("The '{}' shall contain only one entry! Found : {}.", JAdESHeaderParameterNames.ETSI_U, map.size());
					return null;
				}
				return map;

			} else if (etsiUComponent instanceof String) {
				String base64UrlEncoded = (String) etsiUComponent;
				if (isBase64UrlEncoded(base64UrlEncoded)) {
					byte[] itemBinaries = DSSJsonUtils.fromBase64Url(base64UrlEncoded);
					return JsonUtil.parseJson(new String(itemBinaries));
				} else {
					LOG.warn("A String component of '{}' array shall be base64Url encoded!", JAdESHeaderParameterNames.ETSI_U);
				}

			} else {
				LOG.warn("A component of unsupported class '{}' found inside the '{}' array!",
						etsiUComponent.getClass(), JAdESHeaderParameterNames.ETSI_U);
			}

		} catch (Exception e) {
			LOG.warn("An error occurred during '{}' component parsing : {}", JAdESHeaderParameterNames.ETSI_U, e.getMessage(), e);
		}

		return null;
	}

	/**
	 * This method builds {@code SpDocSpecification} from the provided JSON object element
	 *
	 * @param spDocSpecificationObject {@link Object} json object
	 * @return {@link SpDocSpecification}
	 */
	public static SpDocSpecification parseSPDocSpecification(Object spDocSpecificationObject) {
		try {
			Map<?, ?> spDSpec = toMap(spDocSpecificationObject, JAdESHeaderParameterNames.SP_DSPEC);
			if (Utils.isMapEmpty(spDSpec)) {
				LOG.warn("The {} element is empty!", JAdESHeaderParameterNames.SP_DSPEC);
				return null;
			}

			SpDocSpecification spDocSpecification = new SpDocSpecification();

			String id = getAsString(spDSpec, JAdESHeaderParameterNames.ID);
			if (Utils.isStringNotEmpty(id)) {
				spDocSpecification.setId(DSSUtils.getObjectIdentifier(id));
			}

			String desc = getAsString(spDSpec, JAdESHeaderParameterNames.DESC);
			if (Utils.isStringNotEmpty(desc)) {
				spDocSpecification.setDescription(desc);
			}

			List<?> docRefsList = getAsList(spDSpec, JAdESHeaderParameterNames.DOC_REFS);
			if (Utils.isCollectionNotEmpty(docRefsList)) {
				spDocSpecification.setDocumentationReferences(docRefsList.toArray(new String[0]));
			}

			return spDocSpecification;

		} catch (Exception e) {
			LOG.warn("An error occurred during '{}' component parsing : {}", JAdESHeaderParameterNames.SP_DSPEC, e.getMessage(), e);
		}
		return null;
	}

	/**
	 * Converts the {@code JWS} to {@link JWSJsonSerializationObject}
	 *
	 * @param jws {@link JWS} to convert
	 * @return {@link JWSJsonSerializationObject}
	 */
	public static JWSJsonSerializationObject toJWSJsonSerializationObject(JWS jws) {
		JWSJsonSerializationObject jwsJsonSerializationObject = new JWSJsonSerializationObject();
		jwsJsonSerializationObject.getSignatures().add(jws);
		jwsJsonSerializationObject.setPayload(jws.getSignedPayload());
		return jwsJsonSerializationObject;
	}

	/**
	 * This method computes the signing input bytes for a JWS signature
	 *
	 * @param jws {@link JWS} to get signing input for
	 * @return signing input bytes
	 */
	public static byte[] getSigningInputBytes(JWS jws) {
		/*
        https://tools.ietf.org/html/rfc7797#section-3
        +-------+-----------------------------------------------------------+
        | "b64" | JWS Signing Input Formula                                 |
        +-------+-----------------------------------------------------------+
        | true  | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||     |
        |       | BASE64URL(JWS Payload))                                   |
        |       |                                                           |
        | false | ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.') ||    |
        |       | JWS Payload                                               |
        +-------+-----------------------------------------------------------+
		*/
		byte[] dataToSign;

		if (!jws.isRfc7797UnencodedPayload()) {
			String dataToBeSignedString = DSSJsonUtils.concatenate(jws.getEncodedHeader(), jws.getEncodedPayload());
			dataToSign = DSSJsonUtils.getAsciiBytes(dataToBeSignedString);

		} else {
			try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
				// NOTE: unencoded payload shall not be converted to a string, it can lead to a data corruption!
				os.write(DSSJsonUtils.getAsciiBytes(jws.getEncodedHeader()));
				os.write(0x2e); // ascii for "."
				byte[] payloadBytes = jws.getUnverifiedPayloadBytes();
				if (Utils.isArrayNotEmpty(payloadBytes)) {
					os.write(payloadBytes);
				}
				dataToSign = os.toByteArray();

			} catch (IOException e) {
				throw new DSSException(String.format(
						"Unable to compute the JWS Signature Input for the unencoded payload! " +
								"Reason : %s", e.getMessage()), e);
			}

		}

		if (LOG.isTraceEnabled()) {
			LOG.trace("JWS Signature Input: ");
			LOG.trace(new String(dataToSign));
		}

		return dataToSign;
	}

	/**
	 * This method extracts a key set used within a JOSE Header (protected + unprotected)
	 *
	 * @param jws {@link JWS} to extract keys from
	 * @return a set of {@link String} keys
	 */
	public static Set<String> extractJOSEHeaderMembersSet(JWS jws) {
		try {
			Set<String> joseHeaderMemberKeys = new HashSet<>();
			Map<String, Object> signedHeaders = JsonUtil.parseJson(jws.getHeaders().getFullHeaderAsJsonString());
			joseHeaderMemberKeys.addAll(signedHeaders.keySet());
			if (jws.getUnprotected() != null) {
				joseHeaderMemberKeys.addAll(jws.getUnprotected().keySet());
			}
			return joseHeaderMemberKeys;
		} catch (JoseException e) {
			throw new IllegalInputException(String.format(
					"Unable to extract key set from a JOSE header! Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Gets a value from the {@code map} under the given {@code key} as {@code Boolean}
	 *
	 * @param map {@link Map} to extract the value from
	 * @param key {@link String} key
	 * @return {@link Boolean} value when found, null otherwise
	 */
	public static Boolean getAsBoolean(Map<?, ?> map, String key) {
		return toBoolean(map.get(key), key);
	}
	/**
	 * Method safely converts {@code Object} to {@code Boolean} if possible.
	 * The method also provides a user-friendly message explaining the origin of the unexpected variable.
	 *
	 * @param object {@link Object} to convert
	 * @param headerName {@link String} name of the header attribute with the extracted value
	 * @return {@link Boolean} if able to convert, null value otherwise
	 */
	public static Boolean toBoolean(Object object, String headerName) {
		if (object == null) {
			// continue

		} else if (object instanceof Boolean) {
			return (Boolean) object;

		} else if (Utils.isStringNotEmpty(headerName)) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process '{}' header parameter with value : '{}'. The Boolean type is expected!",
						headerName, object);
			} else {
				LOG.warn("Unable to process '{}' header parameter. The Boolean type is expected!", headerName);
			}

		} else {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process an obtained item with value : '{}'. The Boolean type is expected!", object);
			} else {
				LOG.warn("Unable to process an obtained item. The Boolean type is expected!");
			}
		}

		return null;
	}

	/**
	 * Gets a value from the {@code map} under the given {@code key} as {@code String}
	 *
	 * @param map {@link Map} to extract the value from
	 * @param key {@link String} key
	 * @return {@link String} value when found, empty string otherwise
	 */
	public static String getAsString(Map<?, ?> map, String key) {
		return toString(map.get(key), key);
	}

	/**
	 * Method safely converts {@code Object} to {@code String} if possible
	 *
	 * @param object {@link Object} to convert
	 * @return {@link String} if able to convert, empty string otherwise
	 */
	public static String toString(Object object) {
		return toString(object, null);
	}

	/**
	 * Method safely converts {@code Object} to {@code String} if possible.
	 * The method also provides a user-friendly message explaining the origin of the unexpected variable.
	 *
	 * @param object {@link Object} to convert
	 * @param headerName {@link String} name of the header attribute with the extracted value
	 * @return {@link String} if able to convert, empty string otherwise
	 */
	public static String toString(Object object, String headerName) {
		if (object == null) {
			// continue

		} else if (object instanceof String) {
			return (String) object;

		} else if (Utils.isStringNotEmpty(headerName)) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process '{}' header parameter with value : '{}'. The String type is expected!",
						headerName, object);
			} else {
				LOG.warn("Unable to process '{}' header parameter. The String type is expected!", headerName);
			}

		} else {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process an obtained item with value : '{}'. The String type is expected!", object);
			} else {
				LOG.warn("Unable to process an obtained item. The String type is expected!");
			}
		}

		return Utils.EMPTY_STRING;
	}

	/**
	 * Gets a value from the {@code map} under the given {@code key} as {@code Map}
	 *
	 * @param map {@link Map} to extract the value from
	 * @param key {@link String} key
	 * @return {@link Map} value when found, empty map otherwise
	 */
	public static Map<?, ?> getAsMap(Map<?, ?> map, String key) {
		return toMap(map.get(key), key);
	}

	/**
	 * Method safely converts {@code Object} to {@code Map} if possible.
	 *
	 * @param object {@link Object} to convert
	 * @return {@link Map} if able to convert, empty map otherwise
	 */
	public static Map<?, ?> toMap(Object object) {
		return toMap(object, null);
	}

	/**
	 * Method safely converts {@code Object} to {@code Map} if possible.
	 * The method also provides a user-friendly message explaining the origin of the unexpected variable.
	 *
	 * @param object {@link Object} to convert
	 * @param headerName {@link String} name of the header attribute with the extracted value
	 * @return {@link Map} if able to convert, empty map otherwise
	 */
	public static Map<?, ?> toMap(Object object, String headerName) {
		if (object == null) {
			// continue

		} else if (object instanceof Map) {
			return (Map<?, ?>) object;

		} else if (Utils.isStringNotEmpty(headerName)) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process '{}' header parameter with value : '{}'. The JSON Object type is expected!",
						headerName, object);
			} else {
				LOG.warn("Unable to process '{}' header parameter. The JSON Object type is expected!", headerName);
			}

		} else {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process an obtained item with value : '{}'. The JSON Object type is expected!",object);
			} else {
				LOG.warn("Unable to process an obtained item. The JSON Object type is expected!");
			}
		}

		return Collections.emptyMap();
	}

	/**
	 * Gets a value from the {@code map} under the given {@code key} as {@code List}
	 *
	 * @param map {@link Map} to extract the value from
	 * @param key {@link String} key
	 * @return {@link List} value when found, empty list otherwise
	 */
	public static List<?> getAsList(Map<?, ?> map, String key) {
		return toList(map.get(key), key);
	}

	/**
	 * Method safely converts {@code Object} to {@code List} if possible.
	 *
	 * @param object {@link Object} to convert
	 * @return {@link List} if able to convert, empty map otherwise
	 */
	public static List<?> toList(Object object) {
		return toList(object, null);
	}

	/**
	 * Method safely converts {@code Object} to {@code List} if possible.
	 * The method also provides a user-friendly message explaining the origin of the unexpected variable.
	 *
	 * @param object {@link Object} to convert
	 * @param headerName {@link String} name of the header attribute with the extracted value
	 * @return {@link List} if able to convert, empty map otherwise
	 */
	public static List<?> toList(Object object, String headerName) {
		if (object == null) {
			// continue

		} else if (object instanceof List) {
			return (List<?>) object;

		} else if (Utils.isStringNotEmpty(headerName)) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process '{}' header parameter with value : '{}'. The JSON Array type is expected!",
						headerName, object);
			} else {
				LOG.warn("Unable to process '{}' header parameter. The JSON Array type is expected!", headerName);
			}

		} else {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to process an obtained item with value : '{}'. The JSON Array type is expected!", object);
			} else {
				LOG.warn("Unable to process an obtained item. The JSON Array type is expected!");
			}
		}

		return Collections.emptyList();
	}

	/**
	 * Converts a list of objects to a list of {@code String}s
	 *
	 * @param list a list of {@link Object}s
	 * @return list of {@link String}s
	 */
	public static List<String> toListOfStrings(List<?> list) {
		List<String> listOfStrings = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(list)) {
			for (Object item : list) {
				String str = toString(item);
				if (Utils.isStringNotEmpty(str)) {
					listOfStrings.add(str);
				} else {
					LOG.warn("An empty String entry within a JSON Object has been skipped.");
				}
			}
		}
		return listOfStrings;
	}

	/**
	 * Converts a list of objects to a list of {@code Number}s
	 *
	 * @param list a list of {@link Object}s
	 * @return list of {@link Number}s
	 */
	public static List<Number> toListOfNumbers(List<?> list) {
		List<Number> listOfNumbers = new ArrayList<>();
		if (Utils.isCollectionNotEmpty(list)) {
			for (Object item : list) {
				if (item instanceof Number) {
					Number num = (Number) item;
					listOfNumbers.add(num);

				} else {
					if (LOG.isDebugEnabled()) {
						LOG.warn("Unable to process an obtained item with value : '{}'. The Number type is expected!", item);
					} else {
						LOG.warn("Unable to process an obtained item. The Number type is expected!");
					}
				}
			}
		}
		return listOfNumbers;
	}

}
