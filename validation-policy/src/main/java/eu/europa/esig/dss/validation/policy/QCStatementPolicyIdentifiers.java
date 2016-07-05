package eu.europa.esig.dss.validation.policy;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

/**
 * Qualified Certificate Statement constants
 */
public class QCStatementPolicyIdentifiers {

	private QCStatementPolicyIdentifiers() {
	}

	public static final String QC_COMPLIANT = "0.4.0.1862.1.1";

	public static final String QC_SSCD = "0.4.0.1862.1.4";

	public static final String QTC_ESIGN = "0.4.0.1862.1.6.1";

	public static final String QTC_ESEAL = "0.4.0.1862.1.6.2";

	public static final String QTC_WEB = "0.4.0.1862.1.6.3";

	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasQCStatementOID(certificate, QC_SSCD);
	}

	public static boolean isQCCompliant(CertificateWrapper certificate) {
		return hasQCStatementOID(certificate, QC_COMPLIANT);
	}

	private static boolean hasQCStatementOID(CertificateWrapper certificate, String... oids) {
		List<String> qcStatementIds = certificate.getQCStatementIds();
		if (Utils.isCollectionNotEmpty(qcStatementIds)) {
			for (String oid : oids) {
				if (qcStatementIds.contains(oid)) {
					return true;
				}
			}
		}
		return false;
	}

}
