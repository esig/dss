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

import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;

import java.util.ArrayList;
import java.util.List;

/**
 * Handles method logic to process {@code XmlFoundCertificates} and returns wrappers
 *
 */
public class FoundCertificatesProxy {
	
	/** Wrapped {@code XmlFoundCertificates} */
	private XmlFoundCertificates foundCertificates;
	
	/**
	 * Default constructor
	 *
	 * @param foundCertificates {@link XmlFoundCertificates}
	 */
	public FoundCertificatesProxy(final XmlFoundCertificates foundCertificates) {
		this.foundCertificates = foundCertificates;
	}
	
	private XmlFoundCertificates getFoundCertificates() {
		if (foundCertificates == null) {
			foundCertificates = new XmlFoundCertificates();
		}
		return foundCertificates;
	}
	
	/**
	 * Returns a list of related certificates
	 * 
	 * @return a list of {@link RelatedCertificateWrapper}s
	 */
	public List<RelatedCertificateWrapper> getRelatedCertificates() {
		List<RelatedCertificateWrapper> certificateWrappers = new ArrayList<>();
		
		List<XmlRelatedCertificate> relatedCertificates = getFoundCertificates().getRelatedCertificates();
		for (XmlRelatedCertificate relatedCertificate : relatedCertificates) {
			certificateWrappers.add(new RelatedCertificateWrapper(relatedCertificate));
		}
		return certificateWrappers;
	}
	
	/**
	 * Returns a list of orphan certificates
	 * 
	 * @return a list of {@link OrphanCertificateWrapper}s
	 */
	public List<OrphanCertificateWrapper> getOrphanCertificates() {
		List<OrphanCertificateWrapper> orphanTokens = new ArrayList<>();
		
		List<XmlOrphanCertificate> orphanCertificates = getFoundCertificates().getOrphanCertificates();
		for (XmlOrphanCertificate orphanCertificate : orphanCertificates) {
			orphanTokens.add(new OrphanCertificateWrapper(orphanCertificate));
		}
		return orphanTokens;
	}
	
	/**
	 * Returns a list of found related {@code RelatedCertificateWrapper}s with the given {@code origin}
	 * 
	 * @param origin {@link CertificateOrigin} to get certificates with
	 * @return list of {@link RelatedCertificateWrapper}
	 */
	public List<RelatedCertificateWrapper> getRelatedCertificatesByOrigin(CertificateOrigin origin) {
		List<RelatedCertificateWrapper> certificateWrappers = new ArrayList<>();
		
		List<RelatedCertificateWrapper> relatedCertificates = getRelatedCertificates();
		for (RelatedCertificateWrapper relatedCertificate : relatedCertificates) {
			if (relatedCertificate.getOrigins().contains(origin)) {
				certificateWrappers.add(relatedCertificate);
			}
		}
		return certificateWrappers;
	}
	
	/**
	 * Returns a list of found {@code OrphanCertificateTokenWrapper}s with the given {@code origin}
	 * 
	 * @param origin {@link CertificateOrigin} to get certificates with
	 * @return list of {@link OrphanCertificateWrapper}
	 */
	public List<OrphanCertificateWrapper> getOrphanCertificatesByOrigin(CertificateOrigin origin) {
		List<OrphanCertificateWrapper> orphanCertificatesWrappers = new ArrayList<>();
		
		List<OrphanCertificateWrapper> orphanCertificates = getOrphanCertificates();
		for (OrphanCertificateWrapper orphanCertificate : orphanCertificates) {
			if (orphanCertificate.getOrigins().contains(origin)) {
				orphanCertificatesWrappers.add(orphanCertificate);
			}
		}
		return orphanCertificatesWrappers;
	}
	
	/**
	 * Returns a list of found {@code RelatedCertificateWrapper}s with the given reference origin
	 * 
	 * @param refOrigin {@link CertificateRefOrigin} to get certificates with
	 * @return list of {@link RelatedCertificateWrapper}
	 */
	public List<RelatedCertificateWrapper> getRelatedCertificatesByRefOrigin(CertificateRefOrigin refOrigin) {
		List<RelatedCertificateWrapper> certificateWrappers = new ArrayList<>();
		
		List<RelatedCertificateWrapper> relatedCertificates = getRelatedCertificates();
		for (RelatedCertificateWrapper relatedCertificate : relatedCertificates) {
			for (CertificateRefWrapper certificateRef : relatedCertificate.getReferences()) {
				if (refOrigin.equals(certificateRef.getOrigin())) {
					certificateWrappers.add(relatedCertificate);
					break;
				}
			}
		}
		return certificateWrappers;
	}
	
	/**
	 * Returns a list of found {@code OrphanCertificateTokenWrapper}s with the given reference origin
	 * 
	 * @param refOrigin {@link CertificateOrigin} to get certificates with
	 * @return list of {@link OrphanCertificateWrapper}
	 */
	public List<OrphanCertificateWrapper> getOrphanCertificatesByRefOrigin(CertificateRefOrigin refOrigin) {
		List<OrphanCertificateWrapper> orphanCertificatesWrappers = new ArrayList<>();
		
		List<OrphanCertificateWrapper> orphanCertificates = getOrphanCertificates();
		for (OrphanCertificateWrapper orphanCertificate : orphanCertificates) {
			for (CertificateRefWrapper certificateRef : orphanCertificate.getReferences()) {
				if (refOrigin.equals(certificateRef.getOrigin())) {
					orphanCertificatesWrappers.add(orphanCertificate);
					break;
				}
			}
		}
		return orphanCertificatesWrappers;
	}
	
	/**
	 * Returns a list of all found references for related certificates
	 * 
	 * @return a list of {@link CertificateRefWrapper}
	 */
	public List<CertificateRefWrapper> getRelatedCertificateRefs() {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		for (RelatedCertificateWrapper certificateWrapper : getRelatedCertificates()) {
			certificateRefs.addAll(certificateWrapper.getReferences());
		}
		return certificateRefs;
	}
	
	/**
	 * Returns a list of all found references for orphan certificates
	 * 
	 * @return a list of {@link CertificateRefWrapper}
	 */
	public List<CertificateRefWrapper> getOrphanCertificateRefs() {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		for (OrphanCertificateWrapper certificateWrapper : getOrphanCertificates()) {
			certificateRefs.addAll(certificateWrapper.getReferences());
		}
		return certificateRefs;
	}
	
	/**
	 * Returns a list of related certificate references by the given certificate reference origin
	 *
	 * @param refOrigin {@link CertificateRefOrigin}
	 * @return a list of {@link CertificateRefWrapper}s
	 */
	public List<CertificateRefWrapper> getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin refOrigin) {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		for (CertificateRefWrapper ref : getRelatedCertificateRefs()) {
			if (refOrigin.equals(ref.getOrigin())) {
				certificateRefs.add(ref);
			}
		}
		return certificateRefs;
	}
	
	/**
	 * Returns a list of orphan certificate references by the given certificate reference origin
	 *
	 * @param refOrigin {@link CertificateRefOrigin}
	 * @return a list of {@link CertificateRefWrapper}s
	 */
	public List<CertificateRefWrapper> getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin refOrigin) {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		for (CertificateRefWrapper ref : getOrphanCertificateRefs()) {
			if (refOrigin.equals(ref.getOrigin())) {
				certificateRefs.add(ref);
			}
		}
		return certificateRefs;
	}

}
