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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.validation.policy.CryptographicSuiteUtils;

/**
 * Check if DigestAlgorithm is acceptable
 */
public class DigestAlgorithmReliableCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final DigestAlgorithm digestAlgo;

	/** The cryptographic rules */
	private final CryptographicSuite cryptographicSuite;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgo {@link DigestAlgorithm}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param cryptographicSuite {@link CryptographicSuite}
	 */
	protected DigestAlgorithmReliableCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgo, XmlCC result,
										   MessageTag position, CryptographicSuite cryptographicSuite) {
		super(i18nProvider, result, position, cryptographicSuite.getAcceptableDigestAlgoLevel());
		this.digestAlgo = digestAlgo;
		this.cryptographicSuite = cryptographicSuite;
	}

	@Override
	protected boolean process() {
		return CryptographicSuiteUtils.isDigestAlgorithmReliable(cryptographicSuite, digestAlgo);
	}
	
	@Override
	protected XmlMessage buildConstraintMessage() {
		return buildXmlMessage(MessageTag.ASCCM_DAA, getName(digestAlgo));
	}
	
	@Override
	protected XmlMessage buildErrorMessage() {
		if (digestAlgo == null) {
			return buildXmlMessage(MessageTag.ASCCM_DAA_ANS_2, position);
		}
		return buildXmlMessage(MessageTag.ASCCM_DAA_ANS, getName(digestAlgo), position);
	}

}
