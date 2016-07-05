package eu.europa.esig.dss.validation.policy;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;

public final class CertificatePolicyIdentifiers {

	private CertificatePolicyIdentifiers() {
	}

	// ------------ ETSI TS 101 456

	/**
	 * A certificate policy for qualified certificates issued to the public.
	 * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1)
	 * qcp-public(2)}
	 */
	public static final String QCP_PUBLIC = "0.4.0.1456.1.2";

	/**
	 * A certificate policy for qualified certificates issued to the public, requiring use of secure signature-creation
	 * devices.
	 * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1)
	 * qcp-public-with-sscd(1)}
	 */
	public static final String QCP_PUBLIC_WITH_SSCD = "0.4.0.1456.1.1";

	// ------------ ETSI EN 319 411-2

	/**
	 * QCP-n: certificate policy for EU qualified certificates issued to natural persons;
	 * Itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-natural (0)
	 */
	public static final String QCP_NATURAL = "0.4.0.194112.1.0";

	/**
	 * QCP-l: certificate policy for EU qualified certificates issued to legal persons;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-legal (1)
	 */
	public static final String QCP_LEGAL = "0.4.0.194112.1.1";

	/**
	 * QCP-n-qscd: certificate policy for EU qualified certificates issued to natural persons with private key related
	 * to the certified public key in a QSCD;
	 * Itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-natural-qscd (2)
	 */
	public static final String QCP_NATURAL_QSCD = "0.4.0.194112.1.2";

	/**
	 * QCP-l-qscd: certificate policy for EU qualified certificates issued to legal persons with private key related to
	 * the certified public key in a QSCD;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-legal-qscd (3)
	 */
	public static final String QCP_LEGAL_QSCD = "0.4.0.194112.1.3";

	/**
	 * QCP-w: certificate policy for EU qualified website authentication certificates;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-web (4)
	 */
	public static final String QCP_WEB = "0.4.0.194112.1.4";

	public static boolean isSupportedByQSCD(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, QCP_PUBLIC_WITH_SSCD, QCP_LEGAL_QSCD, QCP_NATURAL_QSCD);
	}

	public static boolean isQCP(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, QCP_PUBLIC);
	}

	public static boolean isQCPPlus(CertificateWrapper certificate) {
		return hasPolicyIdOIDs(certificate, QCP_PUBLIC_WITH_SSCD);
	}

	private static boolean hasPolicyIdOIDs(CertificateWrapper certificate, String... oids) {
		List<String> policyIds = certificate.getPolicyIds();
		if (Utils.isCollectionNotEmpty(policyIds)) {
			for (String oid : oids) {
				if (policyIds.contains(oid)) {
					return true;
				}
			}
		}
		return false;
	}

}
