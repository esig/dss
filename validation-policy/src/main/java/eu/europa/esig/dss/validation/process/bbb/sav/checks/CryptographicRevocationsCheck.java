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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;

public class CryptographicRevocationsCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks;
	private final String certificateId;

	public CryptographicRevocationsCheck(T result, List<CryptographicCheck<XmlPSV>> revocationCryptographicChecks, 
			String certificateId) {
		super(result, null);
		this.revocationCryptographicChecks = revocationCryptographicChecks;
		this.certificateId = certificateId;
	}

	@Override
	protected boolean process() {
		// if at least one revocation check successed return true indication
		for (CryptographicCheck<XmlPSV> cryptographicCheck : revocationCryptographicChecks) {
			if (cryptographicCheck.process())
				return true;
		}
		return false;
	}

	@Override
	protected String getAdditionalInfo() {		
		String addInfo = AdditionalInfo.REVOCATION_CRYPTOGRAPHIC_CHECK_FAILURE;
		Object[] params = new Object[] { certificateId };
		return MessageFormat.format(addInfo, params);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ACCCRM;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ACCCRM_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

}
