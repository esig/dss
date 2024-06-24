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

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.Set;

/**
 * This class is used to filter trusted services by the TL Url.
 * 
 */
public class ServiceByTLUrlFilter extends AbstractTrustServiceFilter {

	/** Set of TL URLs to filter by */
	private final Set<String> tlUrls;

	/**
	 * Constructor to instantiate the filter with a single TL URL
	 *
	 * @param tlUrl {@link String}
	 */
	public ServiceByTLUrlFilter(String tlUrl) {
		this(Collections.singleton(tlUrl));
	}

	/**
	 * Constructor to instantiate the filter with a set of TL URLs
	 *
	 * @param tlUrls a set of {@link String}s
	 */
	public ServiceByTLUrlFilter(Set<String> tlUrls) {
		this.tlUrls = tlUrls;
	}

	@Override
	protected boolean isAcceptable(TrustServiceWrapper service) {
		for (String url : tlUrls) {
			if (Utils.areStringsEqualIgnoreCase(url, service.getTrustedList().getUrl())) {
				return true;
			}
		}
		return false;
	}

}
