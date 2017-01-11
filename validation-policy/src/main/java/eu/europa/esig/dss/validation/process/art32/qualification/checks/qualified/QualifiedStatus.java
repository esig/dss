package eu.europa.esig.dss.validation.process.art32.qualification.checks.qualified;

public enum QualifiedStatus {

	/* Not qualifed */
	NOT_QC,

	/* Qualified for electronic signature */
	QC_FOR_ESIGN,

	/* Qualified but not for electronic signature */
	QC_NOT_FOR_ESIGN;

	public static boolean isQC(QualifiedStatus status) {
		return QC_FOR_ESIGN == status || QC_NOT_FOR_ESIGN == status;
	}

}
