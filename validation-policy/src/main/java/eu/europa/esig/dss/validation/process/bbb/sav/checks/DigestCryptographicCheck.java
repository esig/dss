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

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;

public class DigestCryptographicCheck extends AbstractCryptographicCheck<XmlSAV> {
	
	private final DigestAlgorithm digestAlgorithm;
	
	public DigestCryptographicCheck(I18nProvider i18nProvider, XmlSAV result, DigestAlgorithm digestAlgorithm, Date currentTime, CryptographicConstraint constraint) {
		super(i18nProvider, result, currentTime, constraint);
		this.digestAlgorithm = digestAlgorithm;
	}

	@Override
	protected boolean process() {
		
		// Check digest algorithm
		if (!digestAlgorithmIsReliable(digestAlgorithm))
			return false;
		
		// Check digest algorithm expiration date
		if (!digestAlgorithmIsValidOnValidationDate(digestAlgorithm))
			return false;
		
		return true;
		
	}

}
