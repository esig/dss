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
package eu.europa.esig.dss.spi.tsl;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.spi.util.TimeDependentValues;

public class TrustProperties {

	private final Identifier lotlId;
	private final Identifier tlId;
	private final TrustServiceProvider trustServiceProvider;
	private final TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService;

	/**
	 * Constructor for extracted information from an "independent" trusted list
	 * 
	 * @param tlId
	 *                             the TL identifier
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(Identifier tlId, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlId = null;
		this.tlId = tlId;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	/**
	 * Constructor for extracted information from trusted list which is linked to a
	 * LOTL
	 * 
	 * @param lotlId
	 *                             the LOTL identifier
	 * @param tlId
	 *                             the TL identifier
	 * @param trustServiceProvider
	 *                             the trust service provider information
	 * @param trustService
	 *                             the current trust service
	 */
	public TrustProperties(Identifier lotlId, Identifier tlId, TrustServiceProvider trustServiceProvider,
			TimeDependentValues<TrustServiceStatusAndInformationExtensions> trustService) {
		this.lotlId = lotlId;
		this.tlId = tlId;
		this.trustServiceProvider = trustServiceProvider;
		this.trustService = trustService;
	}

	public Identifier getLOTLIdentifier() {
		return lotlId;
	}

	public Identifier getTLIdentifier() {
		return tlId;
	}

	public TrustServiceProvider getTrustServiceProvider() {
		return trustServiceProvider;
	}

	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getTrustService() {
		return trustService;
	}

}
