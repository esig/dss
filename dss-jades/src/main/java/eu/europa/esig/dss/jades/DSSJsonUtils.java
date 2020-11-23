package eu.europa.esig.dss.jades;

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
import eu.europa.esig.dss.jades.validation.JAdESDocumentValidatorFactory;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.jws.JAdESUtils;

/**
 * Utility class for working with JSON objects
 *
 */
public class DSSJsonUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSJsonUtils.class);
	
	public static final String MIME_TYPE_APPLICATION_PREFIX = "application/";
	
	public static final String HTTP_HEADER_DIGEST = "Digest";

	/* RFC 2045 */
	public static final String CONTENT_ENCODING_BINARY = "binary";

	/* Format date-time as specified in RFC 3339 5.6 */
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
	 * Creates a {@link Digest} object from a JSON structure
	 * 
	 * @param digestValueAndAlgo a Map with digAlg and digVal values
	 * @return an instance of Digest or null
	 */
	public static Digest getDigest(Map<?, ?> digestValueAndAlgo) {
		try {
			if (Utils.isMapNotEmpty(digestValueAndAlgo)) {
				String digestAlgoURI = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_ALG);
				String digestValueBase64 = (String) digestValueAndAlgo.get(JAdESHeaderParameterNames.DIG_VAL);
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
		return getOidObject(DSSUtils.getUriOrUrnOid(objectIdentifier), objectIdentifier.getDescription(), 
				objectIdentifier.getDocumentationReferences());
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
		tstContainerParams.put(JAdESHeaderParameterNames.TST_TOKENS, tsTokensArray);
		
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
	 */
	public static byte[] concatenateDSSDocuments(List<DSSDocument> documents) {
		if (Utils.isCollectionEmpty(documents)) {
			throw new DSSException("Unable to build a JWS Payload. Reason : the detached content is not provided!");
		}
		if (documents.size() == 1) {
			return DSSUtils.toByteArray(documents.get(0));
		}

		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSDocument document : documents) {
				baos.write(DSSUtils.toByteArray(document));
			}
			return baos.toByteArray();

		} catch (IOException e) {
			throw new DSSException(String.format("Unable to build a JWS Payload. Reason : %s", e.getMessage()), e);
		}
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
	
	/**
	 * Returns a list of unsigned properties matching the {@code headerName} from the {@code jws}
	 * 
	 * @param jws {@link JWS} to extract unsigned properties from
	 * @param headerName {@link String} name of the unsigned header
	 * @return a list of {@link Object}s
	 */
	public static List<Object> getUnsignedProperties(JWS jws, String headerName) {
		List<Object> etsiU = getEtsiU(jws);
		if (Utils.isCollectionEmpty(etsiU)) {
			return Collections.emptyList();
		}
		
		List<Object> objects = new ArrayList<>();
		
		for (Object item : etsiU) {
			if (item instanceof Map) {
				Map<?, ?> jsonObject = (Map<?, ?>) item;
				Object object = jsonObject.get(headerName);
				if (object != null) {
					objects.add(object);
				}
			}
		}
		
		return objects;
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
	
	/**
	 * Extracts a counter signature from 'cSig' value with respect to the found format
	 * 
	 * @param cSigObject a value of 'cSig' element
	 * @param masterSignature {@link JAdESSignature} the master signature
	 * @return {@link JAdESSignature}
	 */
	@SuppressWarnings("unchecked")
	public static JAdESSignature extractJAdESCounterSignature(Object cSigObject, JAdESSignature masterSignature) {
		
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
					signature.setMasterCSigObject(cSigObject);
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
	 * @return {@link String} containing validation errors, empty string ("") if no error occurred
	 */
	public static String validateAgainstJAdESSchema(JWS jws) {
		StringBuilder builder = new StringBuilder();
		
		String headerJson = jws.getHeaders().getFullHeaderAsJsonString();
		String errors = JAdESUtils.getInstance().validateAgainstJWSProtectedHeaderSchema(headerJson);
		builder.append(errors);
		
		Map<String, Object> unprotected = jws.getUnprotected();
		if (Utils.isMapNotEmpty(unprotected)) {
			String unprotectedJson = JsonUtil.toJson(unprotected);
			errors = JAdESUtils.getInstance().validateAgainstJWSUnprotectedHeaderSchema(unprotectedJson);
			if (Utils.isStringNotEmpty(errors)) {
				builder.append("; ");
				builder.append(errors);
			}
		}
		
		return builder.toString();
	}

}
