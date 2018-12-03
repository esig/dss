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
package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheck;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class TimestampAcceptanceValidation extends AbstractAcceptanceValidation<TimestampWrapper> {

	public TimestampAcceptanceValidation(DiagnosticData diagnosticData, Date currentTime, TimestampWrapper timestamp, ValidationPolicy validationPolicy) {
		super(diagnosticData, timestamp, currentTime, validationPolicy);
	}

	@Override
	protected void initChain() {
		firstItem = timestampCryptographic();

	}

	private ChainItem<XmlSAV> timestampCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(Context.TIMESTAMP);
		return new CryptographicCheck<XmlSAV>(result, token, currentTime, constraint);
	}

}
