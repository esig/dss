package eu.europa.esig.dss.enumerations;

/**
 * This Enumeration defines a list of algorithm described in ETSI TS 119 182-1
 * for incorporation of 'sigD' dictionary (see 5.2.8 The sigD header parameter)
 *
 */
public enum SigDMechanism implements UriBasedEnum {
	
	/**
	 * 5.2.8.2	Mechanism HttpHeaders
	 */
	HTTP_HEADERS("http://uri.etsi.org/19182/HttpHeaders"),

	/**
	 * 5.2.8.3	Mechanism ObjectIdByURI
	 */
	OBJECT_ID_BY_URI("http://uri.etsi.org/19182/ObjectIdByURI"),

	/**
	 * 5.2.8.4	Mechanism ObjectIdByURIHash
	 * 
	 * NOTE: the default signature creation mechanism used by DSS
	 */
	OBJECT_ID_BY_URI_HASH("http://uri.etsi.org/19182/ObjectIdByURIHash"),
	
	/**
	 * Creates a simple DETACHED signature with omitted payload (without SigD element)
	 */
	NO_SIG_D("");
	
	private final String uri;
	
	SigDMechanism(final String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return uri;
	}
	
	/**
	 * Returns a SigDMechanism for the given URI
	 * 
	 * @param uri {@link String} URI representing a SigDMechanism
	 * @return {@link SigDMechanism}
	 */
	public static SigDMechanism forUri(final String uri) {
		for (SigDMechanism sigDMechanism : values()) {
			if (sigDMechanism.getUri().equals(uri)) {
				return sigDMechanism;
			}
		}
		return null;
	}

}
