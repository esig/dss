/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation;

import java.util.HashMap;
import java.util.Map;

public enum SignatureQualification {

	/**
	 * Qualified Electronic Signature
	 */
	QESIG("QESig", "Qualified Electronic Signature"),

	/**
	 * Qualified Electronic Seal
	 */
	QESEAL("QESeal", "Qualified Electronic Seal"),

	/**
	 * Qualified Electronic Signature or Seal
	 */
	QES("QES?", "Qualified Electronic Signature or Seal"),

	/**
	 * Advanced Electronic Signature supported by a Qualified Certificate
	 */
	ADESIG_QC("AdESig-QC", "Advanced Electronic Signature supported by a Qualified Certificate"),

	/**
	 * Advanced Electronic Seal supported by a Qualified Certificate
	 */
	ADESEAL_QC("AdESeal-QC", "Advanced Electronic Seal supported by a Qualified Certificate"),

	/**
	 * Advanced Electronic Signature or Seal supported by a Qualified Certificate
	 */
	ADES_QC("AdES?-QC", "Advanced Electronic Signature or Seal supported by a Qualified Certificate"),

	/**
	 * Advanced Electronic Signature
	 */
	ADESIG("AdESig", "Advanced Electronic Signature"),

	/**
	 * Advanced Electronic Seal
	 */
	ADESEAL("AdESeal", "Advanced Electronic Seal"),

	/**
	 * Advanced Electronic Signature or Seal
	 */
	ADES("AdES?", "Advanced Electronic Signature or Seal"),

	/**
	 * Indeterminate Qualified Electronic Signature
	 */
	INDETERMINATE_QESIG("Indeterminate QESig", "Indeterminate Qualified Electronic Signature"),

	/**
	 * Indeterminate Qualified Electronic Seal
	 */
	INDETERMINATE_QESEAL("Indeterminate QESeal", "Indeterminate Qualified Electronic Seal"),

	/**
	 * Indeterminate Qualified Electronic Signature or Seal
	 */
	INDETERMINATE_QES("Indeterminate QES?", "Indeterminate Qualified Electronic Signature or Seal"),

	/**
	 * Indeterminate Advanced Electronic Signature supported by a Qualified Certificate
	 */
	INDETERMINATE_ADESIG_QC("Indeterminate AdESig-QC", "Indeterminate Advanced Electronic Signature supported by a Qualified Certificate"),

	/**
	 * Indeterminate Advanced Electronic Seal supported by a Qualified Certificate
	 */
	INDETERMINATE_ADESEAL_QC("Indeterminate AdESeal-QC", "Indeterminate Advanced Electronic Seal supported by a Qualified Certificate"),

	/**
	 * Indeterminate Advanced Electronic Signature or Seal supported by a Qualified Certificate
	 */
	INDETERMINATE_ADES_QC("Indeterminate AdES?-QC", "Indeterminate Advanced Electronic Signature or Seal supported by a Qualified Certificate"),

	/**
	 * Indeterminate Advanced Electronic Signature
	 */
	INDETERMINATE_ADESIG("Indeterminate AdESig", "Indeterminate Advanced Electronic Signature"),

	/**
	 * Indeterminate Advanced Electronic Seal
	 */
	INDETERMINATE_ADESEAL("Indeterminate AdESeal", "Indeterminate Advanced Electronic Seal"),

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

	SignatureQualification(String readable, String label) {
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
	 * 
	 * @param value
	 *            the qualification name to be converted to the enum
	 * @return the linked SignatureQualification or null
	 */
	public static SignatureQualification forName(String value) {
		if ((value != null) && !value.isEmpty()) {
			return SignatureQualification.valueOf(value);
		}
		return null;
	}

	/**
	 * SignatureQualification can be null
	 * 
	 * @param readable
	 *            the readable description of the qualification to be converted to the enum
	 * @return the linked SignatureQualification or null
	 */
	public static SignatureQualification fromReadable(String readable) {
		if ((readable != null) && !readable.isEmpty()) {
			return Registry.QUALIFS_BY_READABLE.get(readable);
		}
		return null;
	}

}
