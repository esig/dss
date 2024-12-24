/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.enumerations;

/**
 * Signature profiles (form+level) handled by the SD-DSS framework.
 *
 */
public enum SignatureLevel {

	XML_NOT_ETSI, XAdES_BES, XAdES_EPES, XAdES_T, XAdES_LT, XAdES_C, XAdES_X, XAdES_XL, XAdES_A, XAdES_BASELINE_B, XAdES_BASELINE_T, XAdES_BASELINE_LT, XAdES_BASELINE_LTA,

	CMS_NOT_ETSI, CAdES_BES, CAdES_EPES, CAdES_T, CAdES_LT, CAdES_C, CAdES_X, CAdES_XL, CAdES_A, CAdES_BASELINE_B, CAdES_BASELINE_T, CAdES_BASELINE_LT, CAdES_BASELINE_LTA,

	PDF_NOT_ETSI, PKCS7_B, PKCS7_T, PKCS7_LT, PKCS7_LTA, PAdES_BES, PAdES_EPES, PAdES_LTV, PAdES_BASELINE_B, PAdES_BASELINE_T, PAdES_BASELINE_LT, PAdES_BASELINE_LTA,
	
	JSON_NOT_ETSI, JAdES_BASELINE_B, JAdES_BASELINE_T, JAdES_BASELINE_LT, JAdES_BASELINE_LTA,
	
	UNKNOWN;

	/**
	 * Returns the SignatureLevel based on the name (String)
	 *
	 * @param name
	 *            the signature level's name to retrieve
	 * @return the SignatureLevel
	 */
	public static SignatureLevel valueByName(String name) {
		return valueOf(name.replace('-', '_'));
	}

	@Override
	public String toString() {
		return super.toString().replace('_', '-');
	}

	/**
	 * Returns the corresponding {@code SignatureForm}
	 *
	 * @return the {@link SignatureForm} depending on the {@link SignatureLevel}
	 */
	public SignatureForm getSignatureForm() {
		switch (this) {
			case XML_NOT_ETSI:
			case XAdES_BES:
			case XAdES_EPES:
			case XAdES_T:
			case XAdES_LT:
			case XAdES_C:
			case XAdES_X:
			case XAdES_XL:
			case XAdES_A:
			case XAdES_BASELINE_LTA:
			case XAdES_BASELINE_LT:
			case XAdES_BASELINE_T:
			case XAdES_BASELINE_B:
				return SignatureForm.XAdES;
			case CMS_NOT_ETSI:
			case CAdES_BES:
			case CAdES_EPES:
			case CAdES_T:
			case CAdES_LT:
			case CAdES_C:
			case CAdES_X:
			case CAdES_XL:
			case CAdES_A:
			case CAdES_BASELINE_LTA:
			case CAdES_BASELINE_LT:
			case CAdES_BASELINE_T:
			case CAdES_BASELINE_B:
				return SignatureForm.CAdES;
			case JSON_NOT_ETSI:
			case JAdES_BASELINE_B:
			case JAdES_BASELINE_T:
			case JAdES_BASELINE_LT:
			case JAdES_BASELINE_LTA:
				return SignatureForm.JAdES;
			case PDF_NOT_ETSI:
			case PAdES_BES:
			case PAdES_EPES:
			case PAdES_LTV:
			case PAdES_BASELINE_B:
			case PAdES_BASELINE_T:
			case PAdES_BASELINE_LT:
			case PAdES_BASELINE_LTA:
				return SignatureForm.PAdES;
			case PKCS7_B:
			case PKCS7_T:
			case PKCS7_LT:
			case PKCS7_LTA:
				return SignatureForm.PKCS7;
			case UNKNOWN:
			default:
				throw new UnsupportedOperationException(String.format("The signature level '%s' is not supported!", this));
		}
	}

}
