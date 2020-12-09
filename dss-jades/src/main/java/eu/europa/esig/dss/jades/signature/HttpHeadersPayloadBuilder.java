package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.HTTPHeaderDigest;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Builds payload binaries from HTTPHeaderDocuments for the 'sigD' HttpHeaders mechanism
 * 
 */
public class HttpHeadersPayloadBuilder {
	
	/** The provided detached documents */
	private final List<DSSDocument> detachedContents;

	/**
	 * If the payload shall be computed for a timestamp (defines different processing)
	 */
	private final boolean isTimestamp;

	/**
	 * The default constructor
	 * 
	 * @param detachedContents a list of detached {@link DSSDocument}s
	 * @param isTimestamp     a boolean value defines if the payload shall be
	 *                         computed for a timestamp
	 */
	public HttpHeadersPayloadBuilder(List<DSSDocument> detachedContents, boolean isTimestamp) {
		this.detachedContents = detachedContents;
		this.isTimestamp = isTimestamp;
	}
	
	/**
	 * Builds the payload from HTTPHeaderDocuments
	 * 
	 * @return payload binaries
	 */
	public byte[] build() {
		assertHttpHeadersConfigurationIsValid();

		List<HTTPHeader> httpHeaderDocuments = toHTTPHeaders(detachedContents);
		
		/*
		 * Signing HTTP Messages draft-cavage-http-signatures-10
		 * 
		 * To include the HTTP request target in the signature calculation, use the
		 * special `(request-target)` header field name.
		 * 
		 * 1. If the header field name is `(request-target)` then generate the header
		 * field value by concatenating the lowercased :method, an ASCII space, and the
		 * :path pseudo-headers (as specified in HTTP/2, Section 8.1.2.3 [7]). Note: For
		 * the avoidance of doubt, lowercasing only applies to the :method pseudo-header
		 * and not to the :path pseudo-header.
		 * 
		 * 2. Create the header field string by concatenating the lowercased header
		 * field name followed with an ASCII colon `:`, an ASCII space ` `, and the
		 * header field value. Leading and trailing optional whitespace (OWS) in the
		 * header field value MUST be omitted (as specified in RFC7230 [RFC7230],
		 * Section 3.2.4 [8]). If there are multiple instances of the same header field,
		 * all header field values associated with the header field MUST be
		 * concatenated, separated by a ASCII comma and an ASCII space `, `, and used in
		 * the order in which they will appear in the transmitted HTTP message. Any
		 * other modification to the header field value MUST NOT be made.
		 * 
		 * 3. If value is not the last value then append an ASCII newline `\n`.
		 */
		
		List<HTTPHeader> concatenatedHttpFields = new ArrayList<>();
		
		for (HTTPHeader httpHeader : httpHeaderDocuments) {
			String headerName = Utils.trim(httpHeader.getName());
			String headerValue = Utils.trim(httpHeader.getValue());

			HTTPHeader concatenatedHttpHeader = getHTTPHeaderWithName(concatenatedHttpFields, headerName);

			if (DSSJsonUtils.HTTP_HEADER_DIGEST.equals(headerName) && isTimestamp) {
				if (httpHeader instanceof HTTPHeaderDigest) {
					concatenatedHttpHeader = httpHeader;
					continue;

				} else {
					throw new DSSException("Unable to compute message-imprint for an Archive Timestamp! "
							+ "'Digest' header must be an instance of HTTPHeaderDigest class.");
				}
			}
			
			if (concatenatedHttpHeader != null) {
				StringBuilder stringBuilder = new StringBuilder(concatenatedHttpHeader.getValue());
				stringBuilder.append(", ");
				stringBuilder.append(headerValue);
				headerValue = stringBuilder.toString();

				concatenatedHttpHeader.setValue(headerValue);

			} else {
				concatenatedHttpHeader = new HTTPHeader(headerName, headerValue);
				concatenatedHttpFields.add(concatenatedHttpHeader);
			}
		}
		
		StringBuilder stringBuilder = new StringBuilder();
		Iterator<HTTPHeader> iterator = concatenatedHttpFields.iterator();
		while (iterator.hasNext()) {
			HTTPHeader header = iterator.next();
			if (DSSJsonUtils.HTTP_HEADER_DIGEST.equals(header.getName()) && isTimestamp) {
				HTTPHeaderDigest httpHeaderDigest = (HTTPHeaderDigest) header;
				stringBuilder.append(httpHeaderDigest.getMessageBodyDocument());
			} else {
				stringBuilder.append(Utils.lowerCase(header.getName()));
				stringBuilder.append(":");
				stringBuilder.append(" ");
				stringBuilder.append(header.getValue());
			}
			if (iterator.hasNext()) {
				stringBuilder.append("\n");
			}
		}

		return stringBuilder.toString().getBytes();
	}

	private HTTPHeader getHTTPHeaderWithName(List<HTTPHeader> httpHeaders, String name) {
		for (HTTPHeader httpHeader : httpHeaders) {
			if (name.equals(httpHeader.getName())) {
				return httpHeader;
			}
		}
		return null;
	}

	/**
	 * Casts a list of {@link DSSDocument}s to a list of {@code HTTPHeader}s
	 * 
	 * @param dssDocuments a list of {@link DSSDocument}s to be casted to
	 *                     {@link HTTPHeader}s
	 * @return a list of {@link HTTPHeader}s
	 * @throws IllegalArgumentException if a document of not {@link HTTPHeader}
	 *                                  class found
	 */
	private List<HTTPHeader> toHTTPHeaders(List<DSSDocument> dssDocuments) {
		List<HTTPHeader> httpHeaderDocuments = new ArrayList<>();
		for (DSSDocument document : dssDocuments) {
			if (document instanceof HTTPHeader) {
				HTTPHeader httpHeaderDocument = (HTTPHeader) document;
				httpHeaderDocuments.add(httpHeaderDocument);
			} else {
				throw new IllegalArgumentException(
						String.format("The document with name '%s' is not of type HTTPHeader!", document.getName()));
			}
		}
		return httpHeaderDocuments;
	}

	/**
	 * Checks if a valid detached content is provided for "HTTPHeaders" "sigD"
	 * Mechanism
	 */
	private void assertHttpHeadersConfigurationIsValid() {
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			boolean digestDocumentFound = false;
			for (DSSDocument document : detachedContents) {
				if (!(document instanceof HTTPHeader)) {
					throw new DSSException("The documents to sign must have "
							+ "a type of HTTPHeader for 'sigD' HttpHeaders mechanism!");
				}
				if (DSSJsonUtils.HTTP_HEADER_DIGEST.equals(document.getName())) {
					if (digestDocumentFound) {
						throw new DSSException("Only one 'Digest' header or HTTPHeaderDigest object is allowed!");
					}
					if (!(document instanceof HTTPHeaderDigest) && isTimestamp) {
						throw new DSSException("Unable to compute message-imprint for a Timestamp! "
								+ "'Digest' header must be an instance of HTTPHeaderDigest class.");
					}
					digestDocumentFound = true;
				}
			}
		} else {
			throw new DSSException("Unable to compute HTTPHeaders payload! The list of detached documents is empty.");
		}
	}

}
