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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper for orphan certificate token extracted from a document (signature/timestamp)
 *
 */
public class OrphanCertificateWrapper extends OrphanCertificateTokenWrapper {

	/** The orphan certificate */
	private final XmlOrphanCertificate orphanCertificate;
	
	/**
	 * Default constructor
	 *
	 * @param orphanCertificate {@link XmlOrphanCertificate}
	 */
	public OrphanCertificateWrapper(final XmlOrphanCertificate orphanCertificate) {
		super(orphanCertificate.getToken());
		this.orphanCertificate = orphanCertificate;
	}
	
	/**
	 * Returns a list of orphan certificate origins
	 * 
	 * @return a list of {@link CertificateOrigin}s
	 */
	public List<CertificateOrigin> getOrigins() {
		return orphanCertificate.getOrigins();
	}
	
	/**
	 * Returns a list of orphan certificate references
	 * 
	 * @return a list of {@link CertificateRefWrapper}s
	 */
	public List<CertificateRefWrapper> getReferences() {
		List<CertificateRefWrapper> certificateRefWrappers = new ArrayList<>();
		
		List<XmlCertificateRef> certificateRefs = orphanCertificate.getCertificateRefs();
		for (XmlCertificateRef certificateRef : certificateRefs) {
			certificateRefWrappers.add(new CertificateRefWrapper(certificateRef, getId()));
		}
		return certificateRefWrappers;
	}

}
