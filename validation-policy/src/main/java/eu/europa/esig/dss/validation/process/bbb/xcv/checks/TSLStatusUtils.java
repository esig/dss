package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.TSLConstant;

public final class TSLStatusUtils {

	private TSLStatusUtils() {
	}

	public static boolean isUndersupervision(String status) {
		return TSLConstant.SERVICE_STATUS_UNDERSUPERVISION.equals(status) || TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612.equals(status);
	}

	public static boolean isAccredited(String status) {
		return TSLConstant.SERVICE_STATUS_ACCREDITED.equals(status) || TSLConstant.SERVICE_STATUS_ACCREDITED_119612.equals(status);
	}

	public static boolean isSupervisionInCessation(String status) {
		return TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION.equals(status) || TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION_119612.equals(status);
	}

}
