package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

public enum QualifiedStatus {

	/* Qualified */
	QC("Qualified"),

	/* Not qualifed */
	NOT_QC("Not qualified");

	private final String label;

	private QualifiedStatus(String label) {
		this.label = label;
	}

	public String getLabel() {
		return label;
	}

	public static boolean isQC(QualifiedStatus status) {
		return QC == status;
	}

}
