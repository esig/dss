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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;

public class TimestampWrapper extends AbstractTokenProxy {

	private final XmlTimestamp timestamp;

	public TimestampWrapper(XmlTimestamp timestamp) {
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return timestamp.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return timestamp.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return timestamp.getSigningCertificate();
	}

	public TimestampType getType() {
		return timestamp.getType();
	}
	
	public ArchiveTimestampType getArchiveTimestampType() {
		return timestamp.getArchiveTimestampType();
	}

	public Date getProductionTime() {
		return timestamp.getProductionTime();
	}

	public XmlDigestMatcher getMessageImprint() {
		for (XmlDigestMatcher digestMatcher : getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
				return digestMatcher;
			}
		}
		return null;
	}

	public boolean isMessageImprintDataFound() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataFound();
		}
		return false;
	}

	public boolean isMessageImprintDataIntact() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataIntact();
		}
		return false;
	}

	public String getFilename() {
		return timestamp.getTimestampFilename();
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return timestamp.getDigestMatchers();
	}
	
	/**
	 * Returns a list of all found certificates in the timestamp token
	 * @return
	 */
	public List<XmlFoundCertificate> getAllFoundCertificates() {
		List<XmlFoundCertificate> foundCertificates = new ArrayList<>();
		for (XmlFoundCertificate foundCertificate : getRelatedCertificates()) {
			foundCertificates.add(foundCertificate);
		}
		for (XmlFoundCertificate foundCertificate : getOrphanCertificates()) {
			foundCertificates.add(foundCertificate);
		}
		return foundCertificates;
	}
	
	/**
	 * Returns a list of all related certificates
	 * 
	 * @return a list of {@link XmlRelatedCertificate}s
	 */
	public List<XmlRelatedCertificate> getRelatedCertificates() {
		return timestamp.getFoundCertificates().getRelatedCertificates();
	}

	/**
	 * Returns a list of all orphan certificates
	 * 
	 * @return a list of {@link XmlOrphanCertificate}s
	 */
	public List<XmlOrphanCertificate> getOrphanCertificates() {
		return timestamp.getFoundCertificates().getOrphanCertificates();
	}
	
	/**
	 * Returns a list of found {@link XmlRelatedCertificate}s with the given {@code origin}
	 * @param origin {@link CertificateOrigin} to get certificates with
	 * @return list of {@link XmlRelatedCertificate}
	 */
	public List<XmlRelatedCertificate> getRelatedCertificatesByOrigin(CertificateOrigin origin) {
		List<XmlRelatedCertificate> certificatesByOrigin = new ArrayList<>();
		XmlFoundCertificates foundCertificates = timestamp.getFoundCertificates();
		if (foundCertificates != null) {
			for (XmlRelatedCertificate foundCertificate : foundCertificates.getRelatedCertificates()) {
				if (foundCertificate.getOrigins().contains(origin)) {
					certificatesByOrigin.add(foundCertificate);
				}
			}
		}
		return certificatesByOrigin;
	}
	
	/**
	 * Returns all found certificate references
	 * 
	 * @return a list of {@link XmlCertificateRef}s
	 */
	public List<XmlCertificateRef> getAllFoundCertificateRefs() {
		List<XmlCertificateRef> certificateRefs = getAllRelatedCertificateRefs();
		certificateRefs.addAll(getAllOrphanCertificateRefs());
		return certificateRefs;
	}
	
	/**
	 * Returns a list of all related certificate references
	 * 
	 * @return a list of {@link XmlCertificateRef}s
	 */
	public List<XmlCertificateRef> getAllRelatedCertificateRefs() {
		return getCertificateRefsFromListOfCertificates(getRelatedCertificates());
	}

	/**
	 * Returns a list of all related orphan certificates
	 * 
	 * @return a list of {@link XmlCertificateRef}s
	 */
	public List<XmlCertificateRef> getAllOrphanCertificateRefs() {
		return getCertificateRefsFromListOfCertificates(getOrphanCertificates());
	}
	
	private <T extends XmlFoundCertificate> List<XmlCertificateRef> getCertificateRefsFromListOfCertificates(Collection<T> foundCertificates) {
		List<XmlCertificateRef> certificateRefs = new ArrayList<>();
		if (foundCertificates != null) {
			for (T certificate : foundCertificates) {
				certificateRefs.addAll(certificate.getCertificateRefs());
			}
		}
		return certificateRefs;
	}
	
	/**
	 * Returns a list of found {@link XmlFoundCertificate} containing a reference
	 * from the given {@code origin}
	 * 
	 * @param origin
	 *               {@link CertificateRefOrigin} of a certificate reference
	 * @return list of found {@link XmlFoundCertificate}
	 */
	public List<XmlFoundCertificate> getFoundCertificatesByRefOrigin(CertificateRefOrigin origin) {
		List<XmlFoundCertificate> certificatesByLocation = new ArrayList<>();
		for (XmlFoundCertificate foundCertificate : getAllFoundCertificates()) {
			for (XmlCertificateRef certificateRef : foundCertificate.getCertificateRefs()) {
				if (origin.equals(certificateRef.getOrigin())) {
					certificatesByLocation.add(foundCertificate);
				}
			}
		}
		return certificatesByLocation;
	}
	
	/**
	 * Returns a list of all found revocations
	 * 
	 * @return a list of {@link XmlFoundRevocation}s
	 */
	public List<XmlFoundRevocation> getAllFoundRevocations() {
		List<XmlFoundRevocation> foundRevocations = new ArrayList<>();
		foundRevocations.addAll(getRelatedRevocations());
		foundRevocations.addAll(getOrphanRevocations());
		return foundRevocations;
	}
	
	/**
	 * Returns a list of all related revocations
	 * 
	 * @return a list of {@link XmlRelatedRevocation}s
	 */
	public List<XmlRelatedRevocation> getRelatedRevocations() {
		return timestamp.getFoundRevocations().getRelatedRevocations();
	}
	
	/**
	 * Returns a list of all orphan revocations
	 * 
	 * @return a list of {@link XmlOrphanRevocation}s
	 */
	public List<XmlOrphanRevocation> getOrphanRevocations() {
		return timestamp.getFoundRevocations().getOrphanRevocations();
	}
	
	/**
	 * Returns all found revocation references
	 * 
	 * @return a list of {@link XmlRevocationRef}s
	 */
	public List<XmlRevocationRef> getAllFoundRevocationRefs() {
		List<XmlRevocationRef> revocationRefs = getAllRelatedRevocationRefs();
		revocationRefs.addAll(getAllOrphanRevocationRefs());
		return revocationRefs;
	}
	
	/**
	 * Returns a list of all related revocation references
	 * 
	 * @return a list of {@link XmlRevocationRef}s
	 */
	public List<XmlRevocationRef> getAllRelatedRevocationRefs() {
		return getRevocationRefsFromListOfRevocations(getRelatedRevocations());
	}

	/**
	 * Returns a list of all related orphan references
	 * 
	 * @return a list of {@link XmlRevocationRef}s
	 */
	public List<XmlRevocationRef> getAllOrphanRevocationRefs() {
		return getRevocationRefsFromListOfRevocations(getOrphanRevocations());
	}
	
	private <T extends XmlFoundRevocation> List<XmlRevocationRef> getRevocationRefsFromListOfRevocations(Collection<T> foundRevocations) {
		List<XmlRevocationRef> revocationRefs = new ArrayList<>();
		if (foundRevocations != null) {
			for (T revocation : foundRevocations) {
				revocationRefs.addAll(revocation.getRevocationRefs());
			}
		}
		return revocationRefs;
	}

	/**
	 * Returns a complete list of all {@link XmlTimestampedObject}s covered by the
	 * timestamp
	 * 
	 * @return list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getTimestampedObjects() {
		return timestamp.getTimestampedObjects();
	}

	/**
	 * Returns a list of {@link SignatureWrapper}s covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedSignatureIds() {
		return getTimestampedObjectByCategory(TimestampedObjectType.SIGNATURE);
	}

	/**
	 * Returns a list of certificate ids covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedCertificateIds() {
		List<String> timestampedObjectIds = getTimestampedObjectByCategory(TimestampedObjectType.CERTIFICATE);
		timestampedObjectIds.addAll(getTimestampedOrphanCertificateTokenIds());
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of revocation data ids covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedRevocationIds() {
		List<String> timestampedObjectIds = getTimestampedObjectByCategory(TimestampedObjectType.REVOCATION);
		timestampedObjectIds.addAll(getTimestampedOrphanRevocationTokenIds());
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of timestamp ids covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedTimestampIds() {
		return getTimestampedObjectByCategory(TimestampedObjectType.TIMESTAMP);
	}

	/**
	 * Returns a list of Signed data ids covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedSignedDataIds() {
		return getTimestampedObjectByCategory(TimestampedObjectType.SIGNED_DATA);
	}

	private List<String> getTimestampedObjectByCategory(TimestampedObjectType category) {
		List<String> timestampedObjectIds = new ArrayList<>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (category == timestampedObject.getCategory()) {
				timestampedObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of all OrphanToken ids
	 * 
	 * @return list of ids
	 */
	public List<String> getAllTimestampedOrphanTokenIds() {
		List<String> timestampedObjectIds = new ArrayList<>();
		timestampedObjectIds.addAll(getTimestampedOrphanCertificateTokenIds());
		timestampedObjectIds.addAll(getTimestampedOrphanRevocationTokenIds());
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of OrphanCertificateToken ids by provided
	 * 
	 * @return list of orphan certificate ids
	 */
	public List<String> getTimestampedOrphanCertificateTokenIds() {
		List<String> timestampedObjectIds = new ArrayList<>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (TimestampedObjectType.ORPHAN_CERTIFICATE == timestampedObject.getCategory()) {
				timestampedObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of OrphanRevocationToken ids by provided
	 * 
	 * @return list of orphan revocation ids
	 */
	public List<String> getTimestampedOrphanRevocationTokenIds() {
		List<String> timestampedObjectIds = new ArrayList<>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (TimestampedObjectType.ORPHAN_REVOCATION == timestampedObject.getCategory()) {
				timestampedObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		return timestampedObjectIds;
	}

	@Override
	public byte[] getBinaries() {
		return timestamp.getBase64Encoded();
	}

	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return timestamp.getDigestAlgoAndValue();
	}
	
	/* -------- PAdES RFC3161 Specific parameters --------- */

	/**
	 * Returns a PAdES-specific PDF Revision info
	 * NOTE: applicable only for PAdES
	 * 
	 * @return {@link XmlPDFRevision}
	 */
	public XmlPDFRevision getPDFRevision() {
		return timestamp.getPDFRevision();
	}
	
	/**
	 * Returns the first signature field name
	 * 
	 * @return {@link String} field name
	 */
	public String getFirstFieldName() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignatureFieldName().get(0);
		}
		return null;
	}
	
	/**
	 * Returns a list of signature field names, where the signature is referenced from
	 * 
	 * @return a list of {@link String} signature field names
	 */
	public List<String> getSignatureFieldNames() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignatureFieldName();
		}
		return Collections.emptyList();
	}
	
	/**
	 * Returns a list if Signer Infos (Signer Information Store) from CAdES CMS Signed Data
	 * 
	 * @return list of {@link XmlSignerInfo}s
	 */
	public List<XmlSignerInfo> getSignatureInformationStore() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignerInformationStore();
		}
		return Collections.emptyList();
	}

	public String getSignerName() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignerName();
		}
		return null;
	}

	public String getSignatureDictionaryType() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getType();
		}
		return null;
	}

	public String getFilter() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getFilter();
		}
		return null;
	}

	public String getSubFilter() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSubFilter();
		}
		return null;
	}

	public String getContactInfo() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getContactInfo();
		}
		return null;
	}

	public String getReason() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getReason();
		}
		return null;
	}
	
	public List<BigInteger> getSignatureByteRange() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignatureByteRange();
		}
		return Collections.emptyList();
	}

}
