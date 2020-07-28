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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public class CryptographicCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheck<T> {

	private final TokenProxy token;
	private final CryptographicConstraint constraint;
	private final MessageTag position;

	public CryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position, Date currentTime, CryptographicConstraint constraint) {
		super(i18nProvider, result, currentTime, constraint);
		this.constraint = constraint;
		this.token = token;
		this.position = position;
	}

	@Override
	protected boolean process() {

		// Check if there are any expiration dates
		boolean expirationCheckRequired = isExpirationDateAvailable(constraint);

		// Check encryption algorithm
		if (!encryptionAlgorithmIsReliable(token.getEncryptionAlgorithm()))
			return false;

		// Check digest algorithm
		if (!digestAlgorithmIsReliable(token.getDigestAlgorithm()))
			return false;

		// Check digest algorithm expiration date
		if (expirationCheckRequired) {
			if (!digestAlgorithmIsValidOnValidationDate(token.getDigestAlgorithm())) {
				return false;
			}
		}

		// Check key size
		if (!isPublicKeySizeKnown(token.getKeyLengthUsedToSignThisToken()))
			return false;

		// Check public key size
		if (!publicKeySizeIsAcceptable(token.getEncryptionAlgorithm(), token.getKeyLengthUsedToSignThisToken()))
			return false;

		// Check encryption algorithm expiration date
		if (expirationCheckRequired) {
			if (!encryptionAlgorithmIsValidOnValidationDate(token.getEncryptionAlgorithm(), token.getKeyLengthUsedToSignThisToken())) {
				return false;
			}
		}

		return true;

	}

	@Override
	protected MessageTag getPosition() {
		return position;
	}

	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (Utils.isStringNotEmpty(failedAlgorithm)) {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID, failedAlgorithm, dateTime, token.getId());
		} else {
			return i18nProvider.getMessage(MessageTag.VALIDATION_TIME_WITH_ID, dateTime, token.getId());
		}
	}

}
