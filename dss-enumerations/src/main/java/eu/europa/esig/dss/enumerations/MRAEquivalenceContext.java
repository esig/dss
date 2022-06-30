package eu.europa.esig.dss.enumerations;

public enum MRAEquivalenceContext implements UriBasedEnum {

	QC_COMPLIANCE("http://ec.europa.eu/trust-services/mutualrecognitionagreement/QcCompliance"),

	QC_TYPE("http://ec.europa.eu/trust-services/mutualrecognitionagreement/QcType"),

	QC_QSCD("http://ec.europa.eu/trust-services/mutualrecognitionagreement/QcQSCD");

	private final String uri;

	MRAEquivalenceContext(String uri) {
		this.uri = uri;
	}

	@Override
	public String getUri() {
		return this.uri;
	}

}
