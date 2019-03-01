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

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public class CryptographicCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheck<T> {

	private final TokenProxy token;
	
	public CryptographicCheck(T result, TokenProxy token, Date currentTime, CryptographicConstraint constraint) {
		super(result, currentTime, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		
		// Check encryption algorithm
		if (!encryptionAlgorithmIsReliable(token.getEncryptionAlgoUsedToSignThisToken()))
			return false;
		
		// Check digest algorithm
		if (!digestAlgorithmIsReliable(token.getDigestAlgoUsedToSignThisToken()))
			return false;
		
		// Check public key size
		if (!publicKeySizeIsAcceptable(token.getEncryptionAlgoUsedToSignThisToken(), token.getKeyLengthUsedToSignThisToken()))
			return false;
		
		// Check digest algorithm expiration date
		if (!digestAlgorithmIsValidOnValidationDate(token.getDigestAlgoUsedToSignThisToken()))
			return false;
		
		// Check encryption algorithm expiration date
		if (!encryptionAlgorithmIsValidOnValidationDate(token.getEncryptionAlgoUsedToSignThisToken(), token.getKeyLengthUsedToSignThisToken()))
			return false;
		
		return true;
		
	}

}
