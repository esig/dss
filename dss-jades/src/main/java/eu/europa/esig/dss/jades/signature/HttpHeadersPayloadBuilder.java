package eu.europa.esig.dss.jades.signature;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.utils.Utils;

/**
 * Builds payload binaries from HTTPHeaderDocuments for the 'sigD' HttpHeaders mechanism
 * 
 */
public class HttpHeadersPayloadBuilder {
	
	/** The provided detached documents */
	private final List<HTTPHeader> httpHeaderDocuments;

	/**
	 * The default constructor
	 * 
	 * @param httpHeaderDocuments a list of {@link HTTPHeader}s to be signed
	 */
	public HttpHeadersPayloadBuilder(List<HTTPHeader> httpHeaderDocuments) {
		this.httpHeaderDocuments = httpHeaderDocuments;
	}
	
	/**
	 * Builds the payload from HTTPHeaderDocuments
	 * 
	 * @return payload binaries
	 */
	public byte[] build() {
		
		/*
		 *   Signing HTTP Messages draft-cavage-http-signatures-10
		 * 
		 * To include the HTTP request target in the signature calculation, use
		 * the special `(request-target)` header field name.
		 * 
		 * 1.  If the header field name is `(request-target)` then generate the
		 *     header field value by concatenating the lowercased :method, an
		 *     ASCII space, and the :path pseudo-headers (as specified in
		 *     HTTP/2, Section 8.1.2.3 [7]).  Note: For the avoidance of doubt,
		 *     lowercasing only applies to the :method pseudo-header and not to
		 *     the :path pseudo-header.
		 *     
		 * 2.  Create the header field string by concatenating the lowercased
		 *     header field name followed with an ASCII colon `:`, an ASCII
		 *     space ` `, and the header field value.  Leading and trailing
		 *     optional whitespace (OWS) in the header field value MUST be
		 *     omitted (as specified in RFC7230 [RFC7230], Section 3.2.4 [8]).
		 *     If there are multiple instances of the same header field, all
		 *     header field values associated with the header field MUST be
		 *     concatenated, separated by a ASCII comma and an ASCII space `, `,
		 *     and used in the order in which they will appear in the
		 *     transmitted HTTP message.  Any other modification to the header
		 *     field value MUST NOT be made.
		 *     
		 * 3.  If value is not the last value then append an ASCII newline `\n`.
		 */
		
		Map<String, String> httpFields = new LinkedHashMap<>();
		
		for (HTTPHeader httpHeader : httpHeaderDocuments) {
			String headerValue = httpFields.get(httpHeader.getName());
			
			if (headerValue == null) {
				headerValue = httpHeader.getValue();
			} else {
				StringBuilder stringBuilder = new StringBuilder(headerValue);
				stringBuilder.append(", ");
				stringBuilder.append(httpHeader.getValue());
				headerValue = stringBuilder.toString();
			}
			
			httpFields.put(httpHeader.getName(), headerValue);
		}
		
		StringBuilder stringBuilder = new StringBuilder();
		Iterator<Entry<String, String>> iterator = httpFields.entrySet().iterator();
		while (iterator.hasNext()) {
			Map.Entry<String, String> header = iterator.next();
			stringBuilder.append(Utils.lowerCase(header.getKey()));
			stringBuilder.append(":");
			stringBuilder.append(" ");
			stringBuilder.append(header.getValue());
			if (iterator.hasNext()) {
				stringBuilder.append("\n");
			}
		}
		
		return stringBuilder.toString().getBytes();
	}

}
