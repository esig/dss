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
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.OrphanTokenType;
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
		timestampedObjectIds.addAll(getTimestampedOrphanTokenIdsByType(OrphanTokenType.CERTIFICATE));
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of revocation data ids covered be the current timestamp
	 * 
	 * @return list of ids
	 */
	public List<String> getTimestampedRevocationIds() {
		List<String> timestampedObjectIds = getTimestampedObjectByCategory(TimestampedObjectType.REVOCATION);
		timestampedObjectIds.addAll(getTimestampedOrphanTokenIdsByType(OrphanTokenType.REVOCATION));
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
		List<String> timestampedObjectIds = new ArrayList<String>();
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
		return getTimestampedOrphanTokenIdsByType(null);
	}

	/**
	 * Returns a list of OrphanToken ids by provided
	 * {@code tokenType}
	 * 
	 * @param tokenType
	 *                  {@link OrphanTokenType} to get values for
	 * @return list of ids
	 */
	public List<String> getTimestampedOrphanTokenIdsByType(OrphanTokenType tokenType) {
		List<String> timestampedObjectIds = new ArrayList<String>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (TimestampedObjectType.ORPHAN == timestampedObject.getCategory()) {
				XmlOrphanToken orphanToken = (XmlOrphanToken) timestampedObject.getToken();
				if (tokenType == null || tokenType.equals(orphanToken.getType())) {
					timestampedObjectIds.add(orphanToken.getId());
				}
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
