package eu.europa.esig.dss.xades;

public class DSSNamespace {

	private final String uri;
	private final String prefix;

	public DSSNamespace(String uri, String prefix) {
		this.uri = uri;
		this.prefix = prefix;
	}

	public String getUri() {
		return uri;
	}

	public String getPrefix() {
		return prefix;
	}

}
