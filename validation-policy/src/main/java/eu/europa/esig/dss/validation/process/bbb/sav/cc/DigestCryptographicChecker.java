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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Checks the digest algorithm
 */
public class DigestCryptographicChecker extends AbstractCryptographicChecker {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public DigestCryptographicChecker(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, Date validationDate,
									  MessageTag position, CryptographicConstraint constraint) {
		super(i18nProvider, digestAlgorithm, validationDate, position, constraint);
	}

	@Override
	protected void initChain() {
		
		ChainItem<XmlCC> item = firstItem = digestAlgorithmReliable();
		
		if (isExpirationDateAvailable(digestAlgorithm)) {
			item = item.setNextItem(digestAlgorithmOnValidationTime());
		}
		
	}

}
