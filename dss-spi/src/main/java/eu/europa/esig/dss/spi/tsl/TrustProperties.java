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

import java.io.Serializable;

/**
 * Contains the Trust properties for certificates
 */
public class TrustProperties implements Serializable {

	private static final long serialVersionUID = -7460897343036542905L;

	/** The LOTL id */
	private final Identifier lotlId;

	/** The TL id */
	private final Identifier tlId;

	/** The trustServiceProvider */
	private final TrustServiceProvider trustServiceProvider;

	/** The trustService */
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

	/**
	 * Gets LOTL Id
	 *
	 * @return {@link Identifier}
	 */
	public Identifier getLOTLIdentifier() {
		return lotlId;
	}

	/**
	 * Gets TL Id
	 *
	 * @return {@link Identifier}
	 */
	public Identifier getTLIdentifier() {
		return tlId;
	}

	/**
	 * Gets trust service provider
	 *
	 * @return {@link TrustServiceProvider}
	 */
	public TrustServiceProvider getTrustServiceProvider() {
		return trustServiceProvider;
	}

	/**
	 * Gets trust service
	 *
	 * @return {@link TimeDependentValues}
	 */
	public TimeDependentValues<TrustServiceStatusAndInformationExtensions> getTrustService() {
		return trustService;
	}

}
