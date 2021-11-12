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
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Date;

/**
 * Checks if the revocation data is fresh against its ThisUpdate and NextUpdate time interval
 */
public class RevocationDataFreshCheckWithNullConstraint extends AbstractRevocationFreshCheck {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlRFC}
	 * @param revocationData {@link RevocationWrapper}
	 * @param validationDate {@link Date}
	 * @param constraint {@link LevelConstraint}
	 */
	public RevocationDataFreshCheckWithNullConstraint(I18nProvider i18nProvider, XmlRFC result, RevocationWrapper revocationData, 
			Date validationDate, LevelConstraint constraint) {
		super(i18nProvider, result, revocationData, validationDate, constraint);
	}

	@Override
	protected boolean process() {
		if (revocationData != null && revocationData.getNextUpdate() != null) {
			return isThisUpdateTimeAfterValidationTime();
		}
		return false;
	}

	@Override
	protected long getMaxFreshness() {
		return diff(revocationData.getNextUpdate(), revocationData.getThisUpdate());
	}

	private long diff(Date nextUpdate, Date thisUpdate) {
		long nextUpdateTime = nextUpdate == null ? 0 : nextUpdate.getTime();
		long thisUpdateTime = thisUpdate == null ? 0 : thisUpdate.getTime();
		return nextUpdateTime - thisUpdateTime;
	}

}
