package eu.europa.esig.dss.jades;

import java.util.Objects;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;

/**
 * An HTTP message body, which 'Digest' representation is being signed with 'sigD' HTTP_HEADERS mechanism
 *
 */
@SuppressWarnings("serial")
public class HTTPHeaderDigest extends HTTPHeader {
	
	private final DSSDocument messageBodyDocument;

	public HTTPHeaderDigest(final DSSDocument messageBodyDocument, final DigestAlgorithm digestAlgorithm) {
		super(DSSJsonUtils.HTTP_HEADER_DIGEST, buildInstanceDigestValue(messageBodyDocument, digestAlgorithm));
		this.messageBodyDocument = messageBodyDocument;
	}
	
	private static String buildInstanceDigestValue(DSSDocument document, DigestAlgorithm digestAlgorithm) {
		Objects.requireNonNull(document, "DSSDocument shall be provided!");
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm shall be provided!");
		
		String jwsHttpHeaderAlgo = digestAlgorithm.getHttpHeaderAlgo();
		if (jwsHttpHeaderAlgo == null) {
			throw new DSSException(String.format("The DigestAlgorithm '%s' is not supported for 'sigD' HTTP_HEADERS mechanism. "
					+ "See RFC 5843 for more information.", digestAlgorithm));
		}
		/*
		 * RFC 3230 "Instance Digests in HTTP"
		 * 
		 * 4.2 Instance digests
		 * 
		 * An instance digest is the representation of the output of a digest
		 * algorithm, together with an indication of the algorithm used (and any
		 * parameters).
		 * 
		 * instance-digest = digest-algorithm "="
		 *                       <encoded digest output>
		 */
		
		StringBuilder stringBuilder = new StringBuilder(jwsHttpHeaderAlgo);
		stringBuilder.append("=");
		
		String digest = document.getDigest(digestAlgorithm);
		stringBuilder.append(digest);
		
		return stringBuilder.toString();
	}

	/**
	 * Returns the original HTTP Message Body Document
	 * 
	 * @return {@link DSSDocument}
	 */
	public DSSDocument getMessageBodyDocument() {
		return messageBodyDocument;
	}

}
