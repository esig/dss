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

import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;

import java.util.ArrayList;
import java.util.List;

/**
 * Handles method logic to process {@code XmlFoundRevocations} and returns wrappers
 *
 */
public class FoundRevocationsProxy {
	
	/** Wrapped {@code XmlFoundRevocations} */
	private XmlFoundRevocations foundRevocations;
	
	/**
	 * Default constructor
	 *
	 * @param foundRevocations {@link XmlFoundRevocations}
	 */
	public FoundRevocationsProxy(final XmlFoundRevocations foundRevocations) {
		this.foundRevocations = foundRevocations;
	}
	
	private XmlFoundRevocations getFoundRevocations() {
		if (foundRevocations == null) {
			foundRevocations = new XmlFoundRevocations();
		}
		return foundRevocations;
	}
	
	/**
	 * Returns a list of related revocation data
	 * 
	 * @return a list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationData() {
		List<RelatedRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<XmlRelatedRevocation> relatedRevocations = getFoundRevocations().getRelatedRevocations();
		for (XmlRelatedRevocation relatedRevocation : relatedRevocations) {
			revocationWrappers.add(new RelatedRevocationWrapper(relatedRevocation));
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of orphan revocations
	 * 
	 * @return a list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationData() {
		List<OrphanRevocationWrapper> orphanTokens = new ArrayList<>();
		
		List<XmlOrphanRevocation> orphanRevocations = getFoundRevocations().getOrphanRevocations();
		for (XmlOrphanRevocation orphanRevocation : orphanRevocations) {
			orphanTokens.add(new OrphanRevocationWrapper(orphanRevocation));
		}
		return orphanTokens;
	}
	
	/**
	 * Returns a list of all {@link RelatedRevocationWrapper}s used for the signature validation process
	 * with the given {@code originType}
	 * 
	 * @param originType {@link RevocationOrigin} to get values with
	 * @return list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationsByOrigin(RevocationOrigin originType) {
		List<RelatedRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<RelatedRevocationWrapper> relatedRevocations = getRelatedRevocationData();
		for (RelatedRevocationWrapper relatedRevocation : relatedRevocations) {
			if (relatedRevocation.getOrigins().contains(originType)) {
				revocationWrappers.add(relatedRevocation);
			}
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of all {@link OrphanRevocationWrapper}s used for the signature validation process
	 * with the given {@code originType}
	 * 
	 * @param originType {@link RevocationOrigin} to get values with
	 * @return list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationsByOrigin(RevocationOrigin originType) {
		List<OrphanRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<OrphanRevocationWrapper> orphanRevocationData = getOrphanRevocationData();
		for (OrphanRevocationWrapper orphanRevocation : orphanRevocationData) {
			if (orphanRevocation.getOrigins().contains(originType)) {
				revocationWrappers.add(orphanRevocation);
			}
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of all {@link RelatedRevocationWrapper}s used for the signature validation process
	 * with the given revocation origin
	 * 
	 * @param refOrigin {@link RevocationRefOrigin} to get values with
	 * @return list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationsByRefOrigin(RevocationRefOrigin refOrigin) {
		List<RelatedRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<RelatedRevocationWrapper> relatedRevocations = getRelatedRevocationData();
		for (RelatedRevocationWrapper relatedRevocation : relatedRevocations) {
			for (RevocationRefWrapper revocationRef : relatedRevocation.getReferences()) {
				if (revocationRef.getOrigins().contains(refOrigin)) {
					revocationWrappers.add(relatedRevocation);
					break;
				}
			}
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of all {@link OrphanRevocationWrapper}s used for the signature validation process
	 * with the given reference origin
	 * 
	 * @param refOrigin {@link RevocationRefOrigin} to get values with
	 * @return list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationsByRefOrigin(RevocationRefOrigin refOrigin) {
		List<OrphanRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<OrphanRevocationWrapper> orphanRevocationData = getOrphanRevocationData();
		for (OrphanRevocationWrapper orphanRevocation : orphanRevocationData) {
			for (RevocationRefWrapper refWrappper : orphanRevocation.getReferences()) {
				if (refWrappper.getOrigins().contains(refOrigin)) {
					revocationWrappers.add(orphanRevocation);
					break;
				}
			}
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of all {@link RelatedRevocationWrapper}s used for the signature validation process
	 * with the given {@code type}
	 * 
	 * @param type {@link RevocationType} to get values with
	 * @return list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationsByType(RevocationType type) {
		List<RelatedRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<RelatedRevocationWrapper> relatedRevocationData = getRelatedRevocationData();
		for (RelatedRevocationWrapper relatedRevocation : relatedRevocationData) {
			if (type.equals(relatedRevocation.getRevocationType())) {
				revocationWrappers.add(relatedRevocation);
			}
		}
		return revocationWrappers;
	}


	/**
	 * Returns a list of all {@link OrphanRevocationWrapper}s found in the signature, but not used
	 * during the validation process with the given {@code type}
	 * 
	 * @param type {@link RevocationType} to get values with
	 * @return list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationsByType(RevocationType type) {
		List<OrphanRevocationWrapper> revocationWrappers = new ArrayList<>();
		
		List<OrphanRevocationWrapper> orphanRevocationData = getOrphanRevocationData();
		for (OrphanRevocationWrapper orphanRevocation : orphanRevocationData) {
			if (type.equals(orphanRevocation.getRevocationType())) {
				revocationWrappers.add(orphanRevocation);
			}
		}
		return revocationWrappers;
	}
	
	/**
	 * Returns a list of all found references for related revocations
	 * 
	 * @return a list of {@link RevocationRefWrapper}
	 */
	public List<RevocationRefWrapper> getRelatedRevocationRefs() {
		List<RevocationRefWrapper> revocationRefs = new ArrayList<>();
		for (RelatedRevocationWrapper revocationWrapper : getRelatedRevocationData()) {
			revocationRefs.addAll(revocationWrapper.getReferences());
		}
		return revocationRefs;
	}
	
	/**
	 * Returns a list of all found references for orphan revocations
	 * 
	 * @return a list of {@link RevocationRefWrapper}
	 */
	public List<RevocationRefWrapper> getOrphanRevocationRefs() {
		List<RevocationRefWrapper> revocationRefs = new ArrayList<>();
		for (OrphanRevocationWrapper revocationWrapper : getOrphanRevocationData()) {
			revocationRefs.addAll(revocationWrapper.getReferences());
		}
		return revocationRefs;
	}
	
	/**
	 * Returns a list of related revocation data by the given origin and type
	 * 
	 * @param type {@link RevocationType} type of the revocation data
	 * @param origin {@link RevocationOrigin} origin of the revocation data
	 * @return a list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationsByTypeAndOrigin(RevocationType type, RevocationOrigin origin) {
		List<RelatedRevocationWrapper> allRevocations = new ArrayList<>();
		for (RelatedRevocationWrapper revocationWrapper : getRelatedRevocationsByOrigin(origin)) {
			if (type.equals(revocationWrapper.getRevocationType())) {
				allRevocations.add(revocationWrapper);
			}
		}
		return allRevocations;
	}
	
	/**
	 * Returns a list of orphan revocation data by the given origin and type
	 * 
	 * @param type {@link RevocationType} type of the revocation data
	 * @param origin {@link RevocationOrigin} origin of the revocation data
	 * @return a list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationsByTypeAndOrigin(RevocationType type, RevocationOrigin origin) {
		List<OrphanRevocationWrapper> allRevocations = new ArrayList<>();
		for (OrphanRevocationWrapper revocationWrapper : getOrphanRevocationsByOrigin(origin)) {
			if (type.equals(revocationWrapper.getRevocationType())) {
				allRevocations.add(revocationWrapper);
			}
		}
		return allRevocations;
	}

	/**
	 * Returns a list of related revocation data by the given reference origin and type
	 *
	 * @param type {@link RevocationType} type of the revocation data
	 * @param refOrigin {@link RevocationRefOrigin} origin of a reference of revocation data
	 * @return a list of {@link RelatedRevocationWrapper}s
	 */
	public List<RelatedRevocationWrapper> getRelatedRevocationsByTypeAndRefOrigin(RevocationType type,
																				 RevocationRefOrigin refOrigin) {
		List<RelatedRevocationWrapper> allRevocations = new ArrayList<>();
		for (RelatedRevocationWrapper revocationWrapper : getRelatedRevocationsByRefOrigin(refOrigin)) {
			if (type.equals(revocationWrapper.getRevocationType())) {
				allRevocations.add(revocationWrapper);
			}
		}
		return allRevocations;
	}

	/**
	 * Returns a list of orphan revocation data by the given reference origin and type
	 *
	 * @param type {@link RevocationType} type of the revocation data
	 * @param refOrigin {@link RevocationRefOrigin} reference origin of the revocation data
	 * @return a list of {@link OrphanRevocationWrapper}s
	 */
	public List<OrphanRevocationWrapper> getOrphanRevocationsByTypeAndRefOrigin(RevocationType type,
																				RevocationRefOrigin refOrigin) {
		List<OrphanRevocationWrapper> allRevocations = new ArrayList<>();
		for (OrphanRevocationWrapper revocationWrapper : getOrphanRevocationsByRefOrigin(refOrigin)) {
			if (type.equals(revocationWrapper.getRevocationType())) {
				allRevocations.add(revocationWrapper);
			}
		}
		return allRevocations;
	}

}
