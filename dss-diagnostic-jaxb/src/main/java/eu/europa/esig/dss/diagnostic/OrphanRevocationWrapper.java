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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.enumerations.RevocationOrigin;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper for document embedded revocation data
 *
 */
public class OrphanRevocationWrapper extends OrphanRevocationTokenWrapper {

	/** Orphan revocation data */
	private final XmlOrphanRevocation orphanRevocation;
	
	/**
	 * Default constructor
	 *
	 * @param orphanRevocation {@link XmlOrphanRevocation}
	 */
	public OrphanRevocationWrapper(final XmlOrphanRevocation orphanRevocation) {
		super(orphanRevocation.getToken());
		this.orphanRevocation = orphanRevocation;
	}
	
	/**
	 * Returns a list of orphan revocation origins
	 * 
	 * @return a list of {@link RevocationOrigin}s
	 */
	public List<RevocationOrigin> getOrigins() {
		return orphanRevocation.getOrigins();
	}
	
	/**
	 * Returns a list of orphan revocation references
	 * 
	 * @return a list of {@link RevocationRefWrapper}s
	 */
	public List<RevocationRefWrapper> getReferences() {
		List<RevocationRefWrapper> revocationRefWrappers = new ArrayList<>();
		
		List<XmlRevocationRef> revocationRefs = orphanRevocation.getRevocationRefs();
		for (XmlRevocationRef revocationRef : revocationRefs) {
			revocationRefWrappers.add(new RevocationRefWrapper(revocationRef, orphanRevocation.getToken().getId()));
		}
		return revocationRefWrappers;
	}

}
