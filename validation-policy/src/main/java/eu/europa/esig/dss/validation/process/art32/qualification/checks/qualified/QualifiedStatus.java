package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

public enum QualifiedStatus {

	/* Not qualifed */
	NOT_QC("Not qualified"),

	/* Qualified for electronic signature */
	QC_FOR_ESIGN("Qualified for electronic signature"),

	/* Qualified but not for electronic signature */
	QC_NOT_FOR_ESIGN("Qualified but not for electronic signature");

	private final String label;

	private QualifiedStatus(String label) {
		this.label = label;
	}

	public String getLabel() {
		return label;
	}

	public static boolean isQC(QualifiedStatus status) {
		return QC_FOR_ESIGN == status || QC_NOT_FOR_ESIGN == status;
	}

	public static boolean isForEsign(QualifiedStatus status) {
		return QC_FOR_ESIGN == status;
	}

}
