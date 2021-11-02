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

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper for a {@code XmlRelatedCertificate} object
 *
 */
public class RelatedCertificateWrapper extends CertificateWrapper {
	
	/** Wrapped {@code XmlRelatedCertificate} */
	private final XmlRelatedCertificate relatedCertificate;

	/**
	 * Default constructor
	 *
	 * @param relatedCertificate {@link XmlRelatedCertificate}
	 */
	public RelatedCertificateWrapper(XmlRelatedCertificate relatedCertificate) {
		super(relatedCertificate.getCertificate());
		this.relatedCertificate = relatedCertificate;
	}
	
	/**
	 * Returns a list of certificate token origins
	 *
	 * @return a list of {@link CertificateOrigin}s
	 */
	public List<CertificateOrigin> getOrigins() {
		return relatedCertificate.getOrigins();
	}
	
	/**
	 * Returns a list of certificate token references from the signature
	 *
	 * @return a list of {@link CertificateRefWrapper}s
	 */
	public List<CertificateRefWrapper> getReferences() {
		List<CertificateRefWrapper> references = new ArrayList<>();
		for (XmlCertificateRef certificateRef : relatedCertificate.getCertificateRefs()) {
			references.add(new CertificateRefWrapper(certificateRef, getId()));
		}
		return references;
	}

}
