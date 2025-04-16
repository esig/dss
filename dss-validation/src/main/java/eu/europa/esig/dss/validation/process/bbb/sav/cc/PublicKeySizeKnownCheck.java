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
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Check if EncryptionAlgorithm is public key size is known
 */
public class PublicKeySizeKnownCheck extends AbstractCryptographicCheck {

	/** Used key size */
	private final String keySize;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param keySize {@link String}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param cryptographicSuite {@link CryptographicSuite}
	 */
	protected PublicKeySizeKnownCheck(I18nProvider i18nProvider, String keySize, XmlCC result, MessageTag position,
									  CryptographicSuite cryptographicSuite) {
		super(i18nProvider, result, position, ValidationProcessUtils.getLevelRule(cryptographicSuite.getAcceptableEncryptionAlgorithmsMiniKeySizeLevel()));
		this.keySize = keySize;
	}

	@Override
	protected boolean process() {
		return Utils.isStringDigits(keySize);
	}
	
	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.ASCCM_PKSK);
	}
	
	@Override
	protected XmlMessage buildErrorMessage() {
		return buildXmlMessage(MessageTag.ASCCM_PKSK_ANS, position);
	}

}
