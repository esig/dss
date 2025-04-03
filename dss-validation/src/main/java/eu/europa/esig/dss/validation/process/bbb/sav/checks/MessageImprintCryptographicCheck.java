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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.CryptographicRules;

import java.util.Date;

/**
 * Verifies the message-imprint cryptographic constraints
 */
public class MessageImprintCryptographicCheck extends DigestMatcherCryptographicCheck<XmlSAV> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param result {@link XmlSAV}
	 * @param validationDate {@link Date}
	 * @param constraint {@link CryptographicRules}
	 */
	public MessageImprintCryptographicCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, XmlSAV result,
			Date validationDate, CryptographicRules constraint) {
		super(i18nProvider, digestAlgorithm, result, validationDate, MessageTag.ACCM_POS_MESS_IMP, constraint);
	}

}
