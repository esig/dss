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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Set;

/**
 * This class is used to filter trusted services by country code(s).
 * 
 * That's possible to find trusted certificates in more than one TL (eg : UK +
 * PT)
 *
 */
public class ServiceByCountryFilter extends AbstractTrustedServiceFilter {


	/** Country codes to filter by */
	private final Set<String> countryCodes;

	/**
	 * Constructor to instantiate the filter by a single country code
	 *
	 * @param countryCode {@link String}
	 */
	public ServiceByCountryFilter(String countryCode) {
		this(Collections.singleton(countryCode));
	}

	/**
	 * Constructor to instantiate the filter by a set of single country codes
	 *
	 * @param countryCodes a set of {@link String}s
	 */
	public ServiceByCountryFilter(Set<String> countryCodes) {
		this.countryCodes = countryCodes;
	}

	@Override
	boolean isAcceptable(TrustedServiceWrapper service) {
		for (String countryCode : countryCodes) {
			if (Utils.areStringsEqualIgnoreCase(countryCode, service.getCountryCode())) {
				return true;
			}
		}
		return false;
	}

}
