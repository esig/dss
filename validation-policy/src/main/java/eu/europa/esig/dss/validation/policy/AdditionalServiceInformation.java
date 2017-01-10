package eu.europa.esig.dss.validation.policy;

import java.util.List;

public final class AdditionalServiceInformation {

	private AdditionalServiceInformation() {
	}

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic signatures;
	 */
	private static final String FOR_ESIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic seals;
	 */
	private static final String FOR_ESEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication": in order to further specify the
	 * "Service type identifier" identified service as being provided for web site authentication;
	 */
	private static final String FOR_WEB_AUTHENTICATION = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication";

	public static boolean isForeSignatures(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESIGNATURES);
	}

	public static boolean isForeSeals(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESEALS);
	}

	public static boolean isForWebAuth(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_WEB_AUTHENTICATION);
	}

}
