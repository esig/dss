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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.DigestCryptographicCheck;

public class DigestAlgorithmAcceptanceValidation extends Chain<XmlSAV> {
	
	protected final DigestAlgorithm digestAlgorithm;
	protected final Date currentTime;
	protected final Context context;
	protected final ValidationPolicy validationPolicy;

	public DigestAlgorithmAcceptanceValidation(Date currentTime, DigestAlgorithm digestAlgorithm, ValidationPolicy validationPolicy, Context context) {
		super(new XmlSAV());
		this.digestAlgorithm = digestAlgorithm;
		this.currentTime = currentTime;
		this.validationPolicy = validationPolicy;
		this.context = context;
	}
	
	@Override
	protected void initChain() {
		firstItem = digestCryptographic();
	}

	protected ChainItem<XmlSAV> digestCryptographic() {
		CryptographicConstraint constraint = validationPolicy.getSignatureCryptographicConstraint(context);
		return new DigestCryptographicCheck(result, digestAlgorithm, currentTime, constraint);
	}

}
