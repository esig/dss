package eu.europa.esig.dss.validation.process.qmatrix;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public final class AdditionalServiceInformation {

	private AdditionalServiceInformation() {
	}

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic signatures;
	 */
	public static final String FOR_ESIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic seals;
	 */
	public static final String FOR_ESEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication": in order to further specify the
	 * "Service type identifier" identified service as being provided for web site authentication;
	 */
	public static final String FOR_WEB_AUTHENTICATION = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication";

	public static boolean isForeSignatures(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESIGNATURES);
	}

	public static boolean isForeSeals(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESEALS);
	}

	public static boolean isForeSealsOnly(List<String> additionalServiceInfos) {
		return Utils.collectionSize(additionalServiceInfos) == 1 && isForeSeals(additionalServiceInfos);
	}

	public static boolean isForWebAuth(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_WEB_AUTHENTICATION);
	}

	public static boolean isForWebAuthOnly(List<String> additionalServiceInfos) {
		return Utils.collectionSize(additionalServiceInfos) == 1 && isForWebAuth(additionalServiceInfos);
	}

}
