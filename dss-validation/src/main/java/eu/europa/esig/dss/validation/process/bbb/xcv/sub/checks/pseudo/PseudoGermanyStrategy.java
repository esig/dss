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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.pseudo;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.utils.Utils;

/**
 * Extract pseudo information for German certificates
 *
 */
public class PseudoGermanyStrategy implements PseudoStrategy {

	/** Germany country code */
	private static final String GERMANY_COUNTRY_CODE = "DE";

	/** Suffix used for certificate's pseudo definition within X500 Attributes */
	private static final String PSEUDO_SUFFIX = ":PN";

	/**
	 * Default constructor
	 */
	public PseudoGermanyStrategy() {
		// empty
	}

	@Override
	public String getPseudo(CertificateWrapper certificate) {
		if (GERMANY_COUNTRY_CODE.equals(certificate.getCountryName())) {
			String cn = certificate.getCommonName();
			if (Utils.endsWithIgnoreCase(cn, PSEUDO_SUFFIX)) {
				return cn.replace(PSEUDO_SUFFIX, "");
			}
		}
		return null;
	}

}
