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
package eu.europa.esig.dss;

import eu.europa.esig.dss.x509.SignatureForm;

/**
 * Signature profiles (form+level) handled by the SD-DSS framework.
 *
 */
public enum SignatureLevel {

	XML_NOT_ETSI, XAdES_C, XAdES_X, XAdES_XL, XAdES_A, XAdES_BASELINE_LTA, XAdES_BASELINE_LT, XAdES_BASELINE_T, XAdES_BASELINE_B,

	CMS_NOT_ETSI, CAdES_BASELINE_LTA, CAdES_BASELINE_LT, CAdES_BASELINE_T, CAdES_BASELINE_B, CAdES_101733_C, CAdES_101733_X, CAdES_101733_A,

	PDF_NOT_ETSI, PAdES_BASELINE_LTA, PAdES_BASELINE_LT, PAdES_BASELINE_T, PAdES_BASELINE_B, PAdES_102778_LTV,

	ASiC_S_BASELINE_LTA, ASiC_S_BASELINE_LT, ASiC_S_BASELINE_T, ASiC_S_BASELINE_B,

	ASiC_E_BASELINE_LTA, ASiC_E_BASELINE_LT, ASiC_E_BASELINE_T, ASiC_E_BASELINE_B;

	/**
	 * Returns the SignatureLevel based on the name (String)
	 *
	 * @param name
	 * @return
	 */
	public static SignatureLevel valueByName(String name) {
		return valueOf(name.replace("-", "_"));
	}

	@Override
	public String toString() {
		return super.toString().replace("_", "-");
	}

	/**
	 * @return the {@code SignatureForm} depending on the {@code SignatureLevel}
	 */
	public SignatureForm getSignatureForm() {

		switch (this) {
			case XML_NOT_ETSI:
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
			case CAdES_BASELINE_LTA:
			case CAdES_BASELINE_LT:
			case CAdES_BASELINE_T:
			case CAdES_BASELINE_B:
			case CAdES_101733_A:
			case CAdES_101733_C:
			case CAdES_101733_X:
				return SignatureForm.CAdES;
			case PDF_NOT_ETSI:
			case PAdES_102778_LTV:
			case PAdES_BASELINE_B:
			case PAdES_BASELINE_LT:
			case PAdES_BASELINE_LTA:
			case PAdES_BASELINE_T:
				return SignatureForm.PAdES;
			case ASiC_S_BASELINE_B:
			case ASiC_S_BASELINE_T:
			case ASiC_S_BASELINE_LT:
			case ASiC_S_BASELINE_LTA:
				return SignatureForm.ASiC_S;
			case ASiC_E_BASELINE_B:
			case ASiC_E_BASELINE_T:
			case ASiC_E_BASELINE_LT:
			case ASiC_E_BASELINE_LTA:
				return SignatureForm.ASiC_E;
			default:
				return null;
		}
	}
}
