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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * The abstract cryptographic check
 */
public abstract class AbstractCryptographicCheck extends ChainItem<XmlCC> {

	/** The validating constraint position */
	protected final MessageTag position;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraint {@link LevelRule}
	 */
	protected AbstractCryptographicCheck(I18nProvider i18nProvider, XmlCC result, MessageTag position,
										 LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.position = position;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

	/**
	 * Returns name for a DigestAlgorithm safely
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @return {@link String} name
	 */
	protected String getName(DigestAlgorithm digestAlgorithm) {
		return digestAlgorithm != null ? digestAlgorithm.getName() : "?";
	}

	/**
	 * Returns name for an EncryptionAlgorithm safely
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm}
	 * @return {@link String} name
	 */
	protected String getName(EncryptionAlgorithm encryptionAlgorithm) {
		return encryptionAlgorithm != null ? encryptionAlgorithm.getName() : "?";
	}

}
