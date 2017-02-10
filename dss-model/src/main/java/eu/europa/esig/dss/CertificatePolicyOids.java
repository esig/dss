package eu.europa.esig.dss;

public enum CertificatePolicyOids implements EtsiOid {

	// ------------ ETSI TS 101 456

	/**
	 * A certificate policy for qualified certificates issued to the public.
	 * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1)
	 * qcp-public(2)}
	 */
	QCP_PUBLIC("qcp-public", "0.4.0.1456.1.2"),

	/**
	 * A certificate policy for qualified certificates issued to the public, requiring use of secure signature-creation
	 * devices.
	 * {itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(1456) policy-identifiers(1)
	 * qcp-public-with-sscd(1)}
	 */
	QCP_PUBLIC_WITH_SSCD("qcp-public-with-sscd", "0.4.0.1456.1.1"),

	// ------------ ETSI EN 319 411-2

	/**
	 * QCP-n: certificate policy for EU qualified certificates issued to natural persons;
	 * Itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-natural (0)
	 */
	QCP_NATURAL("qcp-natural", "0.4.0.194112.1.0"),

	/**
	 * QCP-l: certificate policy for EU qualified certificates issued to legal persons;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-legal (1)
	 */
	QCP_LEGAL("qcp-legal", "0.4.0.194112.1.1"),

	/**
	 * QCP-n-qscd: certificate policy for EU qualified certificates issued to natural persons with private key related
	 * to the certified public key in a QSCD;
	 * Itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-natural-qscd (2)
	 */
	QCP_NATURAL_QSCD("qcp-natural-qscd", "0.4.0.194112.1.2"),

	/**
	 * QCP-l-qscd: certificate policy for EU qualified certificates issued to legal persons with private key related to
	 * the certified public key in a QSCD;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-legal-qscd (3)
	 */
	QCP_LEGAL_QSCD("qcp-legal-qscd", "0.4.0.194112.1.3"),

	/**
	 * QCP-w: certificate policy for EU qualified website authentication certificates;
	 * itu-t(0) identified-organization(4) etsi(0) qualified-certificate-policies(194112)
	 * policy-identifiers(1) qcp-web (4)
	 */
	QCP_WEB("qcp-web", "0.4.0.194112.1.4");

	private final String description;
	private final String oid;

	CertificatePolicyOids(String description, String oid) {
		this.description = description;
		this.oid = oid;
	}

	@Override
	public String getOid() {
		return oid;
	}

	@Override
	public String getDescription() {
		return description;
	}

}
