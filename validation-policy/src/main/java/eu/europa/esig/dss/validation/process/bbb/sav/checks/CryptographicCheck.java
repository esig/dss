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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
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
		if (!encryptionAlgorithmIsReliable(token.getEncryptionAlgorithm()))
			return false;
		
		// Check digest algorithm
		if (!digestAlgorithmIsReliable(token.getDigestAlgorithm()))
			return false;
		
		// Check public key size
		if (!publicKeySizeIsAcceptable(token.getEncryptionAlgorithm(), token.getKeyLengthUsedToSignThisToken()))
			return false;
		
		// Check digest algorithm expiration date
		if (!digestAlgorithmIsValidOnValidationDate(token.getDigestAlgorithm()))
			return false;
		
		// Check encryption algorithm expiration date
		if (!encryptionAlgorithmIsValidOnValidationDate(token.getEncryptionAlgorithm(), token.getKeyLengthUsedToSignThisToken()))
			return false;
		
		return true;
		
	}

	@Override
	protected MessageTag getMessageTag() {
		if (token instanceof CertificateWrapper) {
			return MessageTag.ACCCM;
		} else if (token instanceof RevocationWrapper) {
			return MessageTag.ARCCM;
		} else if (token instanceof TimestampWrapper) {
			return MessageTag.ATCCM;
		}
		return super.getMessageTag();
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String addInfo = null;
		Object[] params = null;
		String dateTime = sdf.format(validationDate);
		if (Utils.isStringNotEmpty(failedAlgorithm)) {
			addInfo = AdditionalInfo.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID;
			params = new Object[] { failedAlgorithm, dateTime, token.getId() };
		} else {
			addInfo = AdditionalInfo.VALIDATION_TIME_WITH_ID;
			params = new Object[] { dateTime, token.getId() };
		}
		return MessageFormat.format(addInfo, params);
	}

}
