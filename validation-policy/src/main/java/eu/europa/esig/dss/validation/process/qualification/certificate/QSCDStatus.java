package eu.europa.esig.dss.validation.process.qualification.certificate;

public enum QSCDStatus {

	QSCD,

	NOT_QSCD;

	public static boolean isQSCD(QSCDStatus status) {
		return QSCD == status;
	}

}
