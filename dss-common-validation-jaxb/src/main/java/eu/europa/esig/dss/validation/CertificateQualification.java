package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

public enum CertificateQualification {

	/**
	 * Qualified Certificate for Electronic Signatures with private key on QSCD
	 */
	QCERT_FOR_ESIG_QSCD("QC for eSig with QSCD",
			"Qualified Certificate for Electronic Signatures with private key on QSCD", true, true, true),

	/**
	 * Qualified Certificate for Electronic Seals with private key on QSCD
	 */
	QCERT_FOR_ESEAL_QSCD("QC for eSeal with QSCD",
			"Qualified Certificate for Electronic Seals with private key on QSCD", true, false, true),

	// QCERT_FOR_WSA_QSCD non sense

	// --------------------------------------------------------

	/**
	 * Qualified Certificate for Electronic Signatures
	 */
	QCERT_FOR_ESIG("QC for eSig", "Qualified Certificate for Electronic Signatures", true, true, false),

	/**
	 * Qualified Certificate for Electronic Seals
	 */
	QCERT_FOR_ESEAL("QC for eSeal", "Qualified Certificate for Electronic Seals", true, false, false),

	/**
	 * Qualified Certificate for Web Site Authentications
	 */
	QCERT_FOR_WSA("QC for WSA", "Qualified Certificate for Web Site Authentications", true, false, false),

	// --------------------------------------------------------

	/**
	 * Certificate for Electronic Signatures
	 */
	CERT_FOR_ESIG("Cert for eSig", "Certificate for Electronic Signatures", false, true, false),

	/**
	 * Certificate for Electronic Seals
	 */
	CERT_FOR_ESEAL("Cert for eSeal", "Certificate for Electronic Seals", false, false, false),

	/**
	 * Certificate for Web Site Authentications
	 */
	CERT_FOR_WSA("Cert for WSA", "Certificate for Web Site Authentications", false, false, false),

	/**
	 * Not Applicable
	 */
	NA("N/A", "Not applicable", false, false, false);

	private static class Registry {

		private final static Map<String, CertificateQualification> QUALIFS_BY_READABLE = registerByReadable();

		private static Map<String, CertificateQualification> registerByReadable() {
			final Map<String, CertificateQualification> map = new HashMap<String, CertificateQualification>();
			for (final CertificateQualification qualification : values()) {
				map.put(qualification.readable, qualification);
			}
			return map;
		}
	}

	private final String readable;
	private final String label;
	private final boolean qc;
	private final boolean forEsig;
	private final boolean qscd;

	private CertificateQualification(String readable, String label, boolean qc, boolean forEsig, boolean qscd) {
		this.readable = readable;
		this.label = label;
		this.qc = qc;
		this.forEsig = forEsig;
		this.qscd = qscd;
	}

	public String getReadable() {
		return readable;
	}

	public String getLabel() {
		return label;
	}

	/**
	 * CertificateQualification can be null
	 * 
	 * @param value
	 *            the qualification name to be converted to the enum
	 * @return the linked CertificateQualification or null
	 */
	public static CertificateQualification forName(String value) {
		if ((value != null) && !value.isEmpty()) {
			return CertificateQualification.valueOf(value);
		}
		return null;
	}

	/**
	 * CertificateQualification can be null
	 * 
	 * @param readable
	 *            the readable description of the qualification to be converted to the enum
	 * @return the linked CertificateQualification or null
	 */
	public static CertificateQualification fromReadable(String readable) {
		if ((readable != null) && !readable.isEmpty()) {
			return Registry.QUALIFS_BY_READABLE.get(readable);
		}
		return null;
	}

	public boolean isQc() {
		return qc;
	}

	public boolean isForEsig() {
		return forEsig;
	}

	public boolean isQscd() {
		return qscd;
	}

}
