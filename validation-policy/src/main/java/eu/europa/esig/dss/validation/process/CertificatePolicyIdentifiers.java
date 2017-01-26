package eu.europa.esig.dss.validation.process;

import java.util.List;

import eu.europa.esig.dss.CertificatePolicyOids;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public final class CertificatePolicyIdentifiers {

	private CertificatePolicyIdentifiers() {
	}

	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD, CertificatePolicyOids.QCP_LEGAL_QSCD,
				CertificatePolicyOids.QCP_NATURAL_QSCD);
	}

	public static boolean isQCP(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC);
	}

	public static boolean isQCPPlus(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_PUBLIC_WITH_SSCD);
	}

	public static boolean isLegal(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_LEGAL, CertificatePolicyOids.QCP_LEGAL_QSCD);
	}

	public static boolean isNatural(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, CertificatePolicyOids.QCP_NATURAL, CertificatePolicyOids.QCP_NATURAL_QSCD);
	}

	private static boolean hasPolicyIdOIDs(CertificateWrapper certificate, CertificatePolicyOids... certificatePolicyIds) {
		List<String> policyIds = certificate.getPolicyIds();
		if (Utils.isCollectionNotEmpty(policyIds)) {
			for (CertificatePolicyOids policyId : certificatePolicyIds) {
				if (policyIds.contains(policyId.getOid())) {
					return true;
				}
			}
		}
		return false;
	}

}
