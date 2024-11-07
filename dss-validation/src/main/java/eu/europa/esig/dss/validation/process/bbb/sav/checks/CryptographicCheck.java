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

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicChecker;

import java.util.Date;

/**
 * The cryptographic check
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class CryptographicCheck<T extends XmlConstraintsConclusion> extends CryptographicCheckerResultCheck<T> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param token {@link TokenProxy}
	 * @param position {@link MessageTag}
	 * @param validationDate {@link Date}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public CryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position,
							  Date validationDate, CryptographicConstraint constraint) {
		this(i18nProvider, result, token, position, validationDate, constraint, null);
	}

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param token {@link TokenProxy}
	 * @param position {@link MessageTag}
	 * @param validationDate {@link Date}
	 * @param constraint {@link CryptographicConstraint}
	 * @param tokenId {@link String}
	 */
	protected CryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position,
							  Date validationDate, CryptographicConstraint constraint, String tokenId) {
		super(i18nProvider, result, validationDate, position,
				execute(i18nProvider, token, validationDate, position, constraint), constraint, tokenId);
	}
	
	private static XmlCC execute(I18nProvider i18nProvider, TokenProxy token, Date validationDate,
			MessageTag position, CryptographicConstraint constraint) {
		CryptographicChecker cc = new CryptographicChecker(i18nProvider, token, validationDate, position, constraint);
		return cc.execute();
	}

}
