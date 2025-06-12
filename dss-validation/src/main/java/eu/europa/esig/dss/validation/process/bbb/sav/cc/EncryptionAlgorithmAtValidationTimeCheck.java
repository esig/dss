/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.validation.policy.CryptographicSuiteUtils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Check EncryptionAlgorithm at validation time
 */
public class EncryptionAlgorithmAtValidationTimeCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final EncryptionAlgorithm encryptionAlgo;

	/** The used key size */
	private final String keyLength;

	/** Validation time */
	private final Date validationDate;

	/** The cryptographic rules */
	private final CryptographicSuite cryptographicSuite;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param encryptionAlgo {@link EncryptionAlgorithm}
	 * @param keyLength {@link String}
	 * @param validationDate {@link Date}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param cryptographicSuite {@link CryptographicSuite}
	 */
	protected EncryptionAlgorithmAtValidationTimeCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo,
													   String keyLength, Date validationDate, XmlCC result,
													   MessageTag position, CryptographicSuite cryptographicSuite) {
		super(i18nProvider, result, position, ValidationProcessUtils.getLevelRule(cryptographicSuite.getAlgorithmsExpirationDateLevel()));
		this.encryptionAlgo = encryptionAlgo;
		this.keyLength = keyLength;
		this.validationDate = validationDate;
		this.cryptographicSuite = cryptographicSuite;
	}

	@Override
	protected boolean process() {
		Date expirationDate = CryptographicSuiteUtils.getExpirationDate(cryptographicSuite, encryptionAlgo, keyLength);
		return expirationDate == null || !expirationDate.before(validationDate);
	}

	@Override
	protected Level getLevel() {
		Date algoExpirationDate = CryptographicSuiteUtils.getExpirationDate(cryptographicSuite, encryptionAlgo, keyLength);
		Date cryptographicSuiteUpdateDate = cryptographicSuite.getCryptographicSuiteUpdateDate();
		if (algoExpirationDate != null && cryptographicSuiteUpdateDate != null && cryptographicSuiteUpdateDate.before(algoExpirationDate)) {
			return cryptographicSuite.getAlgorithmsExpirationDateAfterUpdateLevel();
		}
		return super.getLevel();
	}
	
	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.ASCCM_AR, getName(encryptionAlgo));
	}
	
	@Override
	protected XmlMessage buildErrorMessage() {
		return buildXmlMessage(MessageTag.ASCCM_AR_ANS_AKSNR, getName(encryptionAlgo), keyLength, position);
	}

}
