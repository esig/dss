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
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

/**
 * Check if EncryptionAlgorithm is acceptable
 */
public class EncryptionAlgorithmReliableCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final EncryptionAlgorithm encryptionAlgo;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param encryptionAlgo {@link EncryptionAlgorithm}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected EncryptionAlgorithmReliableCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo,
											   XmlCC result, MessageTag position,
											   CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
	}

	@Override
	protected boolean process() {
		return constraintWrapper.isEncryptionAlgorithmReliable(encryptionAlgo);
	}
	
	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.ASCCM_EAA, getName(encryptionAlgo));
	}
	
	@Override
	protected XmlMessage buildErrorMessage() {
		return buildXmlMessage(MessageTag.ASCCM_EAA_ANS, getName(encryptionAlgo), position);
	}

}
