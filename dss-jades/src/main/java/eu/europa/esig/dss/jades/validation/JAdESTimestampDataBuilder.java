package eu.europa.esig.dss.jades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import org.jose4j.json.internal.json_simple.JSONValue;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.jades.JAdESArchiveTimestampType;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public class JAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(JAdESTimestampDataBuilder.class);

	private final JAdESSignature signature;

	public JAdESTimestampDataBuilder(JAdESSignature signature) {
		this.signature = signature;
	}

	@Override
	public DSSDocument getContentTimestampData(TimestampToken timestampToken) {
		return new InMemoryDocument(getSignedDataBinaries());
	}
	
	private byte[] getSignedDataBinaries() {
		try {
			// TODO sigD
			return JAdESUtils.toBase64Url(signature.getJws().getPayloadBytes()).getBytes();
		} catch (JoseException e) {
			throw new DSSException("Unable to extract the payload", e);
		}
	}

	@Override
	public DSSDocument getSignatureTimestampData(TimestampToken timestampToken) {
		return new InMemoryDocument(signature.getSignatureValue());
	}

	@Override
	public DSSDocument getTimestampX1Data(TimestampToken timestampToken) {
		// not supported
		return null;
	}

	@Override
	public DSSDocument getTimestampX2Data(TimestampToken timestampToken) {
		// not supported
		return null;
	}

	@Override
	public DSSDocument getArchiveTimestampData(TimestampToken timestampToken) {
		try {
			byte[] archiveTimestampData = getArchiveTimestampData(timestampToken, null, null);
			return new InMemoryDocument(archiveTimestampData);
		} catch (DSSException e) {
			LOG.error("Unable to get data for TimestampToken with Id '{}'. Reason : {}", timestampToken.getDSSIdAsString(), e.getMessage(), e);
			return null;
		}
	}
	
	/**
	 * Returns ArchiveTimestamp Data for a new Timestamp
	 * 
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @param jadesArchiveTimestampType {@link JAdESArchiveTimestampType}
	 * @return byte array timestamp data
	 */
	public byte[] getArchiveTimestampData(final String canonicalizationMethod, final JAdESArchiveTimestampType jadesArchiveTimestampType) {
		// timestamp creation
		return getArchiveTimestampData(null, canonicalizationMethod, jadesArchiveTimestampType);
	}
	
	protected byte[] getArchiveTimestampData(TimestampToken timestampToken, 
			String canonicalizationMethod, JAdESArchiveTimestampType jadesArchiveTimestampType) {
		
		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get archive timestamp data : {}", (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
		}
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		
		/*
		 * 5.3.6.3 Computation of message-imprint
		 * Absence of timeStamped shall be treated as if it is present with value "all".
		 */
		ArchiveTimestampType archiveTimestampType = timestampToken != null && timestampToken.getArchiveTimestampType() != null ?
				timestampToken.getArchiveTimestampType() : jadesArchiveTimestampType.getAssociatedArchiveTimestampType();
				
		switch (archiveTimestampType) {
			case JAdES_ALL:
				return getAllArchiveTimestampData(timestampToken, canonicalizationMethod);
			case JAdES_PREVIOUS_ARC_TST:
				return getPreviousArchiveTimestampData(timestampToken, canonicalizationMethod);
			default:
				throw new DSSException(String.format("The ArchiveTimestampType '%s' is not supported!", archiveTimestampType));
		}
		
	}

	@SuppressWarnings("unchecked")
	private byte[] getAllArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		JWS jws = signature.getJws();
		
		/*
		 * 5.3.6.3.2 Time-stamping all the contents of the JAdES signature
		 * 
		 * If the value of timeStamped is equal to "all" or it is absent, 
		 * and the etsiU array contains base64url encoded unsigned JSON values, 
		 * then the message imprint computation input shall be the concatenation of 
		 * the components in the order they are listed below:
		 */
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			
			/*
			 * 1) One of the following:
			 *     - The value of payload member, if present.
			 *     - The base64url encoded stream of octets retrieved after processing 
			 *               the sigD header parameter if present.
			 *     - The base64url encoded stream of octets of the detached payload 
			 *               retrieved by other means, (out of the scope of the present document) 
			 *               if both the payload component sigD header parameters are absent.
			 */
			
			baos.write(getSignedDataBinaries());
			
			/*
			 * 2) The character '.'.
			 */
			
			baos.write('.');
			
			/*
			 * 3) The value of protected member, which is also base64url encoded, 
			 *    followed by the character '.'.
			 */
			
			baos.write(jws.getEncodedHeader().getBytes());
			baos.write('.');
			
			/*
			 * 4) The value of the signature member, which is the base64url encoded JWS Signature Value.
			 */
			
			baos.write(jws.getEncodedSignature().getBytes());
			
			/*
			 * 5) The result of taking the contents of the etsiU array in the order 
			 * they appear within the array, and concatenating them to the final octet stream. 
			 * While concatenating, the following rules apply:
			 * 
			 * NOTE: There is a difference in computation depending on base64Url value
			 */
			
			boolean base64UrlEncoded = !jws.isRfc7797UnencodedPayload();
			
			List<Object> etsiU = JAdESUtils.getEtsiU(jws);
			
			/*
			 * a) the xVals JSON array shall be incorporated, base64url encoded, 
			 * into the signature if it is not already present and the signature 
			 * misses some of the certificates listed in clause 5.3.5.1 that are required 
			 * to validate the JAdES signature;
			 * b) the rVals JSON object shall be incorporated, base64url encoded, into 
			 * the signature if it is not already present and the signature misses some of 
			 * the revocation data listed in clause 5.3.5.2 that are required to validate 
			 * the JAdES signature;
			 * c) the axVals JSON array shall be incorporated, base64url encoded, into 
			 * the signature if not already present and the following conditions are true: 
			 * attribute certificate(s) or signed assertions have been incorporated into 
			 * the signature, and the signature misses some certificates required for their 
			 * validation; and
			 * d) the arVals JSON object shall be incorporated, base64url encoded, into 
			 * the signature if not already present and the following conditions are true: 
			 * attribute certificates or signed assertions have been incorporated into 
			 * the signature, and the signature misses some revocation values required for 
			 * their validation.
			 * 
			 * NOTE: all the required data is incorporated in LT-level if needed
			 */
			
			for (Object item : etsiU) {
				
				if (!(item instanceof Map<?, ?>)) {
					LOG.warn("Unsupported element is found in 'etsiU'. Shall be a map. The element is skipped for a message imprint computation!");
					continue;
				}
				
				Map<String, Object> map = (Map<String, Object>) item;
				
				if (map.size() != 1) {
					LOG.warn("A child of 'etsiU' shall contain only one entry! Found : {}. "
							+ "The element is skipped for message a imprint computation!", map.size());
					continue;
				}
				
				Object entry = map.values().iterator().next();
				
				// Validation : check is the current timestamp has been reached
				if (timestampToken != null && timestampToken.getHashCode() == entry.hashCode()) {
					// the timestamp is found, stop the iteration
					break;
				}
				
				if (base64UrlEncoded) {
					baos.write(JAdESUtils.toBase64Url(entry).getBytes());
				} else {
					baos.write(getCanonicalizedValue(entry, canonicalizationMethod));
				}
				
			}

			byte[] messageImprint = baos.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("The 'all' timestamp message-imprint : {}", new String(messageImprint));
			}
			
			return messageImprint;
			
			
		} catch (IOException e) {
			throw new DSSException("An error occurred during building of a message imprint");
		}
	}
	
	/*
	 * 5.3.6.3.1	Time-stamping the time-stamp token of the last arcTst
	 * 
	 * If the value of timeStamped is equal to "previousArcTst" the time-stamp tokens 
	 * within the container shall time-stamp the last existing arcTst container in 
	 * the JAdES signature and its associated tstVD, if it is required to generate and 
	 * incorporate it into the JAdES signature. In consequence the message imprint 
	 * computation input shall be either the last existing arcTst container, or 
	 * the concatenation of this container and its associated tstVD, either canonicalized or not.
	 */
	@SuppressWarnings("unchecked")
	private byte[] getPreviousArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		List<Object> etsiU = JAdESUtils.getEtsiU(signature.getJws());
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
		
			boolean previousArcTstFound = false;
			boolean associatedTstVdFound = false;
			
			ListIterator<Object> iterator = etsiU.listIterator(etsiU.size());
			while (!previousArcTstFound && iterator.hasPrevious()) {
				Map<String, Object> previous = (Map<String, Object>) iterator.previous();
	
				Map<String, Object> tstVd = (Map<String, Object>) previous.get(JAdESHeaderParameterNames.TST_VD);
				if (tstVd != null) {
					if (associatedTstVdFound) {
						throw new DSSException("Two consecuitive 'tstVd' containers found! Not valid JAdES. Extension is not possible.");
					}
					associatedTstVdFound = true;
					
					// TODO : check base64url encoded ???
					baos.write(getCanonicalizedValue(tstVd, canonicalizationMethod));
				}
				
				Map<String, Object> arcTst = (Map<String, Object>) previous.get(JAdESHeaderParameterNames.ARC_TST);
				if (arcTst != null) {
					
					// Validation : check if the current timestamp has been reached
					if (timestampToken != null && timestampToken.getHashCode() == arcTst.hashCode()) {
						// reset the previously written data
						baos.reset();
						// go to the next element
						continue;
					}
					
					previousArcTstFound = true;

					// TODO : check base64url encoded ???
					baos.write(getCanonicalizedValue(arcTst, canonicalizationMethod));
				}
			}
			
			if (!previousArcTstFound) {
				LOG.warn("Previous archive timestamp is not found! Message imprint has not been not calculated!");
			}
			
			byte[] messageImprint = baos.toByteArray();

			if (LOG.isTraceEnabled()) {
				LOG.trace("The 'previousArcTst' timestamp message-imprint : {}", new String(messageImprint));
			}
			
			return messageImprint;
			
		} catch (IOException e) {
			throw new DSSException("An error occurred during building of a message imprint");
		}
		
	}
	
	private byte[] getCanonicalizedValue(Object jsonObject, String canonicalizationMethod) {
		// TODO: canonicalization is not implemented yet
		if (canonicalizationMethod != null) {
			LOG.warn("Canonicalization is not supported in the current version. The message imprint computation can lead to an unexpected result");
		}
		// temporary solution
		String jsonString = JSONValue.toJSONString(jsonObject);
		return jsonString.getBytes();
	}

}
