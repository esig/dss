package eu.europa.esig.dss.enumerations;

/**
 * It specifies the current status of the MRA for the corresponding
 * trust service type identified in the TrustServiceLegalIdentifier field.
 *
 */
public enum MRAStatus implements UriBasedEnum {

	/** Used to denote a valid status */
	ENACTED("http://ec.europa.eu/tools/lotl/mra/enacted"),

	/** Used to denote an invalid status */
	REPEALED("http://ec.europa.eu/tools/lotl/mra/repealed");


	/** Identifies URI of the MRA status */
	private final String uri;

	/**
	 * Default constructor
	 *
	 * @param uri {@link String}
	 */
	MRAStatus(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return this.uri;
	}

}
