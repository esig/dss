package eu.europa.esig.dss.enumerations;

/**
 * Enumeration with the possible encoding for PKI encapsulation.
 * 
 * ETSI EN 319 132-1 5.1.3
 */
public enum PKIEncoding implements UriBasedEnum {

	DER("http://uri.etsi.org/01903/v1.2.2#DER"),

	BER("http://uri.etsi.org/01903/v1.2.2#BER"),

	CER("http://uri.etsi.org/01903/v1.2.2#CER"),

	PER("http://uri.etsi.org/01903/v1.2.2#PER"),

	XER("http://uri.etsi.org/01903/v1.2.2#XER");

	private final String uri;

	private PKIEncoding(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}

}
