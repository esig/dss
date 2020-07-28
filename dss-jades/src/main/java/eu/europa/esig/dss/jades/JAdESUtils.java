package eu.europa.esig.dss.jades;

import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.ADO_TST;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_D;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PID;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PL;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_T;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_ATS;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_CM;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ObjectIdentifier;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESUtils {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESUtils.class);
	
	public static final String MIME_TYPE_APPLICATION_PREFIX = "application/";
	
	public static final String HTTP_HEADER_DIGEST = "Digest";

	/* Format date-time as specified in RFC 3339 5.6 */
	private static final String DATE_TIME_FORMAT_RFC3339 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
	
	/**
	 * Contains header names that are supported to be present in the critical attribute
	 */
	private static final Set<String> criticalHeaders;
	
	/**
	 * Contains a list of headers that MUST NOT be incorporated into a 'crit' header (includes RFC 7515, RFC 7518) 
	 */
	private static final Set<String> criticalHeaderExceptions;
	
	static {
		criticalHeaders = Stream.of(
				/* JAdES EN 119-812 constraints */
				SIG_T, X5T_O, SR_CM, SIG_PL, SR_ATS, ADO_TST, SIG_PID, SIG_D,
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
	
	private JAdESUtils() {
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
	 * Returns a base64Url encoded string from the provided JSON Object or JSON Array
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
	 * @param base64UrlEncoded the tring to decoded
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
			byte[] decoded = Base64Url.decode(str);
			return Utils.isArrayNotEmpty(decoded);
		} catch (Exception e) {
			return false;
		}
	}
	
	/**
	 * Checks if the payload is JWS URL safe
	 * See RFC 7797 : 5.2. Unencoded JWS Compact Serialization Payload
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
	 * Returns set of supported critical headers
	 * 
	 * @return set of supported critical header strings
	 */
	public static Set<String> getSupportedCriticalHeaders() {
		return criticalHeaders;
	}

	/**
	 * Returns set of critical header exceptions (see RFC 7515)
	 * 
	 * @return set of critical header exception strings
	 */
	public static Set<String> getCriticalHeaderExceptions() {
		return criticalHeaderExceptions;
	}
	
	/**
	 * Creates a 'DigAlgVal' JsonObject from the given values
	 * 
	 * @param digestValue a byte array representing a hash value
	 * @param digestAlgorithm {@link DigestAlgorithm} has been used to generate the value
	 * @return 'DigAlgVal' {@link JsonObject}
	 */
	public static JsonObject getDigAlgValObject(byte[] digestValue, DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(digestValue, "digestValue must be defined!");
		Objects.requireNonNull(digestAlgorithm, "digestAlgorithm must be defined!");
		
		Map<String, Object> digAlgValParams = new LinkedHashMap<>();
		digAlgValParams.put(JAdESHeaderParameterNames.DIG_ALG, digestAlgorithm.getUri());
		digAlgValParams.put(JAdESHeaderParameterNames.DIG_VAL, Utils.toBase64(digestValue));
		
		return new JsonObject(digAlgValParams);
	}

	/**
	 * Creates a {@link Digest} object from a JSON structure
	 * 
	 * @param digestValueAndAlgo a Map with digAlg and digVal values
	 * @return an instance of Digest or null
	 */
	public static Digest getDigest(Map<?, ?> digestValueAndAlgo) {
		if (Utils.isMapNotEmpty(digestValueAndAlgo)) {
			String digestAlgoURI = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_ALG);
			String digestValueBase64 = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_VAL);
			if (Utils.isStringNotEmpty(digestAlgoURI) && Utils.isStringNotEmpty(digestValueBase64)) {
				return new Digest(DigestAlgorithm.forXML(digestAlgoURI), Utils.fromBase64(digestValueBase64));
			}
		}
		return null;
	}

	/**
	 * Creates an 'oid' LinkedJSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param uri {@link String} URI defining the object.
	 * @return 'oid' {@link JsonObject}
	 */
	public static JsonObject getOidObject(String uri) {
		return getOidObject(uri, null, null);
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
	 * Creates an 'oid' LinkedJSONObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param objectIdentifier {@link ObjectIdentifier} to create an 'oid' from
	 * @return 'oid' {@link JsonObject}
	 */
	public static JsonObject getOidObject(ObjectIdentifier objectIdentifier) {
		return getOidObject(getUriOrUrnOid(objectIdentifier), objectIdentifier.getDescription(), 
				Arrays.asList(objectIdentifier.getDocumentationReferences()));
	}

	/**
	 * Creates an 'oid' JsonObject according to EN 119-182 ch. 5.4.1 The oId data type
	 * 
	 * @param uri {@link String} URI defining the object. The property is REQUIRED.
	 * @param desc {@link String} the object description. The property is OPTIONAL.
	 * @param docRefs a list of {@link String} URIs containing any other additional information about the object. 
	 * 				The property is OPTIONAL.
	 * @return 'oid' {@link JsonObject}
	 */
	public static JsonObject getOidObject(String uri, String desc, List<String> docRefs) {
		Objects.requireNonNull(uri, "uri must be defined!");
		
		Map<String, Object> oidParams = new LinkedHashMap<>();
		oidParams.put(JAdESHeaderParameterNames.ID, uri);
		if (Utils.isStringNotEmpty(desc)) {
			oidParams.put(JAdESHeaderParameterNames.DESC, desc);
		}
		if (Utils.isCollectionNotEmpty(docRefs)) {
			oidParams.put(JAdESHeaderParameterNames.DOC_REFS, new JSONArray(docRefs));
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
			throw new DSSException("Impossible to create 'tstContainer'. List of TimestampBinaries cannot be null or empty!");
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
		tstContainerParams.put(JAdESHeaderParameterNames.TS_TOKENS, tsTokensArray);
		
		return new JsonObject(tstContainerParams);
	}
	
	/**
	 * Creates a 'tstToken' JsonObject according to EN 119-182 ch. 5.4.3.3 The tstContainer type
	 * 
	 * @param timestampToken {@link TimestampToken}s to incorporate
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
	 * @return a byte array of document octets
	 * @throws IOException if an exception occurs
	 */
	public static byte[] concatenateDSSDocuments(List<DSSDocument> documents) throws IOException {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				baos.write(DSSUtils.toByteArray(document));
			}
			return baos.toByteArray();
		}
	}
	
	/**
	 * Casts a list of {@link DSSDocument}s to a list of {@code HTTPHeader}s
	 * 
	 * @param dssDocuments a list of {@link DSSDocument}s to be casted to {@link HTTPHeader}s
	 * @return a list of {@link HTTPHeader}s
	 * @throws IllegalArgumentException if a document of not {@link HTTPHeader} class found
	 */
	public static List<HTTPHeader> toHTTPHeaders(List<DSSDocument> dssDocuments) {
		List<HTTPHeader> httpHeaderDocuments = new ArrayList<>();
		for (DSSDocument document : dssDocuments) {
			if (document instanceof HTTPHeader) {
				HTTPHeader httpHeaderDocument = (HTTPHeader) document;
				httpHeaderDocuments.add(httpHeaderDocument);
			} else {
				throw new IllegalArgumentException(String.format("The document with name '%s' is not of type HTTPHeader!", document.getName()));
			}
		}
		return httpHeaderDocuments;
	}
	
	/**
	 * Checks if the provided document is JSON document
	 * 
	 * @param document {@link DSSDocument} to check
	 * @return TRUE of the document is JSON, FALSE otherwise
	 */
	public static boolean isJsonDocument(DSSDocument document) {
		if (document instanceof DigestDocument || document instanceof HTTPHeader) {
			if (LOG.isDebugEnabled()) {
				LOG.debug("The provided document of class '{}' cannot be parsed as JSON.", document.getClass());
			}
			return false;
		}
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
		return false;
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
		return (List<Object>) unprotected.get(JAdESHeaderParameterNames.ETSI_U);
	}

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

	public static IssuerSerial getIssuerSerial(String value) {
		if (Utils.isStringNotEmpty(value) && Utils.isBase64Encoded(value)) {
			byte[] binary = Utils.fromBase64(value);
			return DSSASN1Utils.getIssuerSerial(binary);
		}
		return null;
	}

	public static String generateKid(CertificateToken signingCertificate) {
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(signingCertificate);
		return Utils.toBase64(DSSASN1Utils.getDEREncoded(issuerSerial));
	}

}
