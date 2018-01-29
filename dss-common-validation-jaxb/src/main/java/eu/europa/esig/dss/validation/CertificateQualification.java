package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

public enum CertificateQualification {

	/**
	 * Qualified Certificate for Electronic Signatures with private key on QSCD
	 */
	QCERT_FOR_ESIG_QSCD("QC Cert for ESig with QSCD", "Qualified Certificate for Electronic Signatures with private key on QSCD"),

	/**
	 * Qualified Certificate for Electronic Seals with private key on QSCD
	 */
	QCERT_FOR_ESEAL_QSCD("QC Cert for ESeal with QSCD", "Qualified Certificate for Electronic Seals with private key on QSCD"),

	// QCERT_FOR_WSA_QSCD non sense

	// --------------------------------------------------------

	/**
	 * Qualified Certificate for Electronic Signatures
	 */
	QCERT_FOR_ESIG("QC Cert for ESig", "Qualified Certificate for Electronic Signatures"),

	/**
	 * Qualified Certificate for Electronic Seals
	 */
	QCERT_FOR_ESEAL("QC Cert for ESeal", "Qualified Certificate for Electronic Seals"),

	/**
	 * Qualified Certificate for Web Site Authentications
	 */
	QCERT_FOR_WSA("QC Cert for WSA", "Qualified Certificate for Web Site Authentications"),

	// --------------------------------------------------------

	/**
	 * Certificate for Electronic Signatures
	 */
	CERT_FOR_ESIG("Cert for ESig", "Certificate for Electronic Signatures"),

	/**
	 * Certificate for Electronic Seals
	 */
	CERT_FOR_ESEAL("Cert for ESeal", "Certificate for Electronic Seals"),

	/**
	 * Certificate for Web Site Authentications
	 */
	CERT_FOR_WSA("Cert for WSA", "Certificate for Web Site Authentications"),

	/**
	 * Not Applicable
	 */
	NA("N/A", "Not applicable");

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

	private CertificateQualification(String readable, String label) {
		this.readable = readable;
		this.label = label;
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

}
