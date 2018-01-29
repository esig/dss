package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks.qscd;

public enum QSCDStatus {

	QSCD,

	NOT_QSCD;

	public static boolean isQSCD(QSCDStatus status) {
		return QSCD == status;
	}

}
