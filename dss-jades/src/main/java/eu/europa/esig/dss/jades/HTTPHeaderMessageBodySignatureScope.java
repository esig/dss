package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.model.Digest;

/**
 * The signature scope used to define the HTTPHeader message body
 */
public class HTTPHeaderMessageBodySignatureScope extends HTTPHeaderSignatureScope {

	/**
	 * The default constructor
	 *
	 * @param digest {@link Digest} of the document
	 */
	public HTTPHeaderMessageBodySignatureScope(Digest digest) {
		super(digest);
	}

	/**
	 * Constructor with a document name
	 *
	 * @param documentName {@link String} document name
	 * @param digest {@link Digest} of the document
	 */
	public HTTPHeaderMessageBodySignatureScope(String documentName, Digest digest) {
		super(documentName, digest);
	}

	@Override
	public String getDescription() {
		return "Message body value digest";
	}

}
