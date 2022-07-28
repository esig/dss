package eu.europa.esig.dss.enumerations;

public enum MRAStatus implements UriBasedEnum {

	ENACTED("http://ec.europa.eu/tools/lotl/mra/enacted"),

	REPEALED("http://ec.europa.eu/tools/lotl/mra/repealed");

	private final String uri;

	MRAStatus(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return this.uri;
	}

}
