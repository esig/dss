/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.validation.items.ItemValidator;

public class CAdESSignerRulesExternalDataValidator implements ItemValidator {

	private CAdESSignature cadesSignature;
	private Boolean externalSignedData;
	
	public CAdESSignerRulesExternalDataValidator(CAdESSignature cadesSignature, Boolean externalData) {
		this.cadesSignature = cadesSignature;
		this.externalSignedData = externalData;
	}

	/**
	 * True if signed data is external to CMS structure
     * False if signed data part of CMS structure
     * Not present if either allowed
	 */
	@Override
	public boolean validate() {
		if (externalSignedData != null) {
			if (!(cadesSignature.getCmsSignedData().getSignedContent() != null ^ externalSignedData)) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	public String getErrorDetail() {
		return null;
	}
}
