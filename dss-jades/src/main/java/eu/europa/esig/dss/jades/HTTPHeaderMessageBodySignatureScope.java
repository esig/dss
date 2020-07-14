package eu.europa.esig.dss.jades;

import eu.europa.esig.dss.model.Digest;

public class HTTPHeaderMessageBodySignatureScope extends HTTPHeaderSignatureScope {

	public HTTPHeaderMessageBodySignatureScope(Digest digest) {
		super(digest);
	}

	public HTTPHeaderMessageBodySignatureScope(String documentName, Digest digest) {
		super(documentName, digest);
	}

	@Override
	public String getDescription() {
		return "Message body value digest";
	}

}
