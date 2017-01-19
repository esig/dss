package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

public enum SignatureQualification {

	/**
	 * Qualified Electronic Signature
	 */
	QESIG("QESig", "Qualified Electronic Signature"),

	/**
	 * Qualified Electronic Signature or Seal
	 */
	QES_NOT_SIG("QES not Sign", "Qualified Electronic Signature or Seal"),

	/**
	 * Advanced Electronic Signature supported by a Qualified Certificate
	 */
	ADESIG_QC("AdESig-QC", "Advanced Electronic Signature supported by a Qualified Certificate"),

	/**
	 * Advanced Electronic Signature or Seal supported by a Qualified Certificate
	 */
	ADES_QC_NOT_SIG("AdES-QC not Sig", "Advanced Electronic Signature or Seal supported by a Qualified Certificate"),

	/**
	 * Advanced Electronic Signature
	 */
	ADESIG("AdESig", "Advanced Electronic Signature"),

	/**
	 * Advanced Electronic Signature or Seal
	 */
	ADES("AdES?", "Advanced Electronic Signature or Seal"),

	/**
	 * Indeterminate Qualified Electronic Signature
	 */
	INDETERMINATE_QESIG("Indeterminate QESig", "Indeterminate Qualified Electronic Signature"),

	/**
	 * Indeterminate Qualified Electronic Signature or Seal
	 */
	INDETERMINATE_QES_NOT_SIG("Indeterminate QES not Sign", "Indeterminate Qualified Electronic Signature or Seal"),

	/**
	 * Indeterminate Advanced Electronic Signature supported by a Qualified Certificate
	 */
	INDETERMINATE_ADESIG_QC("Indeterminate AdESig-QC", "Indeterminate Advanced Electronic Signature supported by a Qualified Certificate"),

	/**
	 * Indeterminate Advanced Electronic Signature or Seal supported by a Qualified Certificate
	 */
	INDETERMINATE_ADES_QC_NOT_SIG("Indeterminate AdES-QC not Sign", "Indeterminate Advanced Electronic Signature or Seal supported by a Qualified Certificate"),

	/**
	 * Indeterminate Advanced Electronic Signature
	 */
	INDETERMINATE_ADESIG("Indeterminate AdESig", "Indeterminate Advanced Electronic Signature"),

	/**
	 * Indeterminate Advanced Electronic Signature or Seal
	 */
	INDETERMINATE_ADES("Indeterminate AdES?", "Indeterminate Advanced Electronic Signature or Seal"),

	/**
	 * Not Advanced Electronic Signature but supported by a Qualified Certificate
	 */
	NOT_ADES_QC_QSCD("Not AdES but QC with QSCD", "Not Advanced Electronic Signature but supported by a Qualified Certificate"),

	/**
	 * Not Advanced Electronic Signature but supported by a Qualified Certificate
	 */
	NOT_ADES_QC("Not AdES but QC", "Not Advanced Electronic Signature but supported by a Qualified Certificate"),

	/**
	 * Not Advanced Electronic Signature
	 */
	NOT_ADES("Not AdES", "Not Advanced Electronic Signature"),

	/**
	 * Not Applicable
	 */
	NA("N/A", "Not applicable");

	private static class Registry {

		private final static Map<String, SignatureQualification> QUALIFS_BY_READABLE = registerByReadable();

		private static Map<String, SignatureQualification> registerByReadable() {
			final Map<String, SignatureQualification> map = new HashMap<String, SignatureQualification>();
			for (final SignatureQualification qualification : values()) {
				map.put(qualification.readable, qualification);
			}
			return map;
		}
	}

	private final String readable;
	private final String label;

	private SignatureQualification(String readable, String label) {
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
	 * SignatureQualification can be null
	 */
	public static SignatureQualification forName(String value) {
		if ((value != null) && !value.isEmpty()) {
			return SignatureQualification.valueOf(value);
		}
		return null;
	}

	/**
	 * SignatureQualification can be null
	 */
	public static SignatureQualification fromReadable(String readable) {
		if ((readable != null) && !readable.isEmpty()) {
			return Registry.QUALIFS_BY_READABLE.get(readable);
		}
		return null;
	}

}
