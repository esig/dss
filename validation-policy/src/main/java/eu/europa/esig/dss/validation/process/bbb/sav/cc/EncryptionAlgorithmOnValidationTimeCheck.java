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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Date;

/**
 * Check EncryptionAlgorithm in validation time
 */
public class EncryptionAlgorithmOnValidationTimeCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final EncryptionAlgorithm encryptionAlgo;

	/** The used key size */
	private final String keySize;

	/** Validation time */
	private final Date validationDate;

	/** The error message if occurred */
	private MessageTag errorMessage;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param encryptionAlgo {@link EncryptionAlgorithm}
	 * @param keySize {@link String}
	 * @param validationDate {@link Date}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected EncryptionAlgorithmOnValidationTimeCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo,
													   String keySize, Date validationDate, XmlCC result,
													   MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
		this.keySize = keySize;
		this.validationDate = validationDate;
	}

	@Override
	protected boolean process() {
		Integer keyLength = Integer.parseInt(keySize);
		Date expirationDate = constraintWrapper.getExpirationDate(encryptionAlgo.getName(), keyLength);
		if (expirationDate == null) {
			errorMessage = MessageTag.ASCCM_AR_ANS_AEDND;
			return false;
		}
		if (expirationDate.before(validationDate)) {
			errorMessage = MessageTag.ASCCM_AR_ANS_AKSNR;
			return false;
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_AR, encryptionAlgo);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		if (MessageTag.ASCCM_AR_ANS_AKSNR.equals(errorMessage)) {
			return buildXmlName(errorMessage, encryptionAlgo, keySize, position);
		} else {
			return buildXmlName(errorMessage, encryptionAlgo, position);
		}
	}

}
