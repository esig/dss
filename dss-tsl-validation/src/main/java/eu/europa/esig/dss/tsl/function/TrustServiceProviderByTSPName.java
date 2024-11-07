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
package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;

/**
 * Filters TrustServicesProviders by TSP name
 *
 */
public class TrustServiceProviderByTSPName implements TrustServiceProviderPredicate {

	/** The TSP name */
	private final String tspName;

	/**
	 * Default constructor
	 *
	 * @param tspName {@link String} to filter by
	 */
	public TrustServiceProviderByTSPName(String tspName) {
		this.tspName = tspName;
	}

	@Override
	public boolean test(TSPType trustServiceProvider) {
		if (trustServiceProvider != null && Utils.isStringNotEmpty(tspName)) {
			TSPInformationType tspInformation = trustServiceProvider.getTSPInformation();
			InternationalNamesType currentTspNames = tspInformation.getTSPName();
			for (MultiLangNormStringType name : currentTspNames.getName()) {
				if (Utils.areStringsEqualIgnoreCase(tspName, name.getValue())) {
					return true;
				}
			}
		}
		return false;
	}

}