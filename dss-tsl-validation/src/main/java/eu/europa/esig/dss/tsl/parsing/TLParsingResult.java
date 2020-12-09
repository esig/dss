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
package eu.europa.esig.dss.tsl.parsing;

import eu.europa.esig.dss.spi.tsl.TrustServiceProvider;

import java.util.List;

/**
 * Parsed TL result
 */
public class TLParsingResult extends AbstractParsingResult {

	/** List of found trust service providers */
	private List<TrustServiceProvider> trustServiceProviders;

	/**
	 * Default constructor
	 */
	public TLParsingResult() {
		super();
	}

	/**
	 * Gets trust service providers
	 *
	 * @return a list of {@link TrustServiceProvider}s
	 */
	public List<TrustServiceProvider> getTrustServiceProviders() {
		return trustServiceProviders;
	}

	/**
	 * Sets trust service providers
	 *
	 * @param trustServiceProviders a list of {@link TrustServiceProvider}s
	 */
	public void setTrustServiceProviders(List<TrustServiceProvider> trustServiceProviders) {
		this.trustServiceProviders = trustServiceProviders;
	}

}
