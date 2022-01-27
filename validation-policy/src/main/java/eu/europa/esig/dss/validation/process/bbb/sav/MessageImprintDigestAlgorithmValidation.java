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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.MessageImprintCryptographicCheck;

import java.util.Date;

/**
 * Verifies cryptographical validity of a DigestAlgorithm used for message-imprint creation
 *
 */
public class MessageImprintDigestAlgorithmValidation extends Chain<XmlSAV> {

	/** DigestAlgorithm to be verified */
	private final DigestAlgorithm digestAlgorithm;

	/** The validation time */
	private final Date currentTime;

	/** Set of cryptographical constraint to validate against */
	private final CryptographicConstraint constraint;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public MessageImprintDigestAlgorithmValidation(I18nProvider i18nProvider, Date currentTime,
			DigestAlgorithm digestAlgorithm, CryptographicConstraint constraint) {
		super(i18nProvider, new XmlSAV());
		this.digestAlgorithm = digestAlgorithm;
		this.currentTime = currentTime;
		this.constraint = constraint;
	}

	@Override
	protected MessageTag getTitle() {
		return MessageTag.DAAV;
	}

	@Override
	protected void initChain() {
		firstItem = messageImprintCryptographic();
	}

	private ChainItem<XmlSAV> messageImprintCryptographic() {
		return new MessageImprintCryptographicCheck(i18nProvider, digestAlgorithm, result, currentTime, constraint);
	}

}
