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
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicRules;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Runs the cryptographic validation
 */
public class CryptographicChecker extends AbstractCryptographicChecker {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param token {@link TokenProxy} to validate
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param cryptographicRules {@link CryptographicRules}
	 */
	public CryptographicChecker(I18nProvider i18nProvider, TokenProxy token, Date validationDate, MessageTag position,
								CryptographicRules cryptographicRules) {
		super(i18nProvider, token.getEncryptionAlgorithm(), token.getDigestAlgorithm(),
				token.getKeyLengthUsedToSignThisToken(), validationDate, position, cryptographicRules);
	}

	@Override
	protected void initChain() {
		
		ChainItem<XmlCC> item = firstItem = encryptionAlgorithmReliable();
		
		item = item.setNextItem(digestAlgorithmReliable());
		
		if (isExpirationDateAvailable(digestAlgorithm)) {
			item = item.setNextItem(digestAlgorithmOnValidationTime());
		}
		
		item = item.setNextItem(publicKeySizeKnown());
		
		item = item.setNextItem(publicKeySizeAcceptable());
		
		if (isExpirationDateAvailable(encryptionAlgorithm, keyLengthUsedToSignThisToken)) {
			item = item.setNextItem(encryptionAlgorithmOnValidationTime());
		}
		
	}

}
