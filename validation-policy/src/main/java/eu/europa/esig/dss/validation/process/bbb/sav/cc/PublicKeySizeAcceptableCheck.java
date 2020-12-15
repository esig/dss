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
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Map;

/**
 * Check if public key size is acceptable
 */
public class PublicKeySizeAcceptableCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final EncryptionAlgorithm encryptionAlgo;

	/** Used public key size */
	private final String keySize;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param encryptionAlgo {@link EncryptionAlgorithm}
	 * @param keySize {@link String}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected PublicKeySizeAcceptableCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo, String keySize, 
			XmlCC result, MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
		this.keySize = keySize;
	}

	@Override
	protected boolean process() {
		String algoToFind = encryptionAlgo == null ? Utils.EMPTY_STRING : encryptionAlgo.getName();
		Map<String, Integer> minimumKeySizes = constraintWrapper.getMinimumKeySizes();
		if (Utils.isMapNotEmpty(minimumKeySizes)) {
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}
	
			Integer expectedMinimumKeySize = minimumKeySizes.get(algoToFind);
			if (tokenKeySize < expectedMinimumKeySize) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_APKSA, encryptionAlgo, keySize);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(MessageTag.ASCCM_APKSA_ANS, encryptionAlgo, keySize, position);
	}

}
