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
import java.util.Objects;

import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;

public class TimestampWrapper extends AbstractTokenProxy {

	private final XmlTimestamp timestamp;
	
	public TimestampWrapper(XmlTimestamp timestamp) {
		Objects.requireNonNull(timestamp, "XmlTimestamp cannot be null!");
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

	/**
	 * Returns FoundCertificatesProxy to access embedded certificates
	 * 
	 * @return {@link FoundCertificatesProxy}
	 */
	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(timestamp.getFoundCertificates());
	}

	/**
	 * Returns FoundRevocationsProxy to access embedded revocation data
	 * 
	 * @return {@link FoundRevocationsProxy}
	 */
	@Override
	public FoundRevocationsProxy foundRevocations() {
		return new FoundRevocationsProxy(timestamp.getFoundRevocations());
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
	 * @return list of {@link SignatureWrapper}s
	 */
	public List<SignatureWrapper> getTimestampedSignatures() {
		List<SignatureWrapper> signatures = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.SIGNATURE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlSignature) {
				signatures.add(new SignatureWrapper((XmlSignature) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNATURE));
			}
		}
		return signatures;
	}

	/**
	 * Returns a list of certificates covered be the current timestamp
	 * 
	 * @return list of {@link CertificateWrapper}s
	 */
	public List<CertificateWrapper> getTimestampedCertificates() {
		List<CertificateWrapper> certificates = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.CERTIFICATE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlCertificate) {
				certificates.add(new CertificateWrapper((XmlCertificate) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.CERTIFICATE));
			}
		}
		return certificates;
	}

	/**
	 * Returns a list of revocation data covered be the current timestamp
	 * 
	 * @return list of {@link RevocationWrapper}s
	 */
	public List<RevocationWrapper> getTimestampedRevocations() {
		List<RevocationWrapper> revocations = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.REVOCATION);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlRevocation) {
				revocations.add(new RevocationWrapper((XmlRevocation) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.REVOCATION));
			}
		}
		return revocations;
	}

	/**
	 * Returns a list of timestamps covered be the current timestamp
	 * 
	 * @return list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTimestampedTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.TIMESTAMP);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlTimestamp) {
				timestamps.add(new TimestampWrapper((XmlTimestamp) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.TIMESTAMP));
			}
		}
		return timestamps;
	}

	/**
	 * Returns a list of Signed data covered be the current timestamp
	 * 
	 * @return list of {@link SignerDataWrapper}s
	 */
	public List<SignerDataWrapper> getTimestampedSignedData() {
		List<SignerDataWrapper> timestamps = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.SIGNED_DATA);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlSignerData) {
				timestamps.add(new SignerDataWrapper((XmlSignerData) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNED_DATA));
			}
		}
		return timestamps;
	}

	public boolean isSigningCertificateIdentified() {
		CertificateWrapper signingCertificate = getSigningCertificate();
		CertificateRefWrapper signingCertificateReference = getSigningCertificateReference();
		if (signingCertificate != null && signingCertificateReference != null) {
			return signingCertificateReference.isDigestValueMatch() && 
					(!signingCertificateReference.isIssuerSerialPresent() || signingCertificateReference.isIssuerSerialMatch());
		}
		return false;
	}

	private List<XmlAbstractToken> getTimestampedObjectsByCategory(TimestampedObjectType category) {
		List<XmlAbstractToken> timestampedObjectIds = new ArrayList<>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (category == timestampedObject.getCategory()) {
				timestampedObjectIds.add(timestampedObject.getToken());
			}
		}
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of all OrphanTokens
	 * 
	 * @return list of {@link OrphanTokenWrapper}s
	 */
	public List<OrphanTokenWrapper> getAllTimestampedOrphanTokens() {
		List<OrphanTokenWrapper> timestampedObjectIds = new ArrayList<>();
		timestampedObjectIds.addAll(getTimestampedOrphanCertificates());
		timestampedObjectIds.addAll(getTimestampedOrphanRevocations());
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of OrphanCertificateTokens
	 * 
	 * @return list of orphan certificates
	 */
	public List<OrphanTokenWrapper> getTimestampedOrphanCertificates() {
		List<OrphanTokenWrapper> orphanCertificates = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanCertificateToken) {
				orphanCertificates.add(new OrphanTokenWrapper((XmlOrphanCertificateToken) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_CERTIFICATE));
			}
		}
		return orphanCertificates;
	}

	/**
	 * Returns a list of OrphanRevocationTokens
	 * 
	 * @return list of orphan revocations
	 */
	public List<OrphanTokenWrapper> getTimestampedOrphanRevocations() {
		List<OrphanTokenWrapper> orphanRevocations = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_REVOCATION);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanRevocationToken) {
				orphanRevocations.add(new OrphanTokenWrapper((XmlOrphanRevocationToken) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_REVOCATION));
			}
		}
		return orphanRevocations;
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
	
	public boolean arePdfModificationsDetected() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return arePdfModificationsDetected(pdfRevision);
	}
	
	/**
	 * Returns a list of PDF annotation overlap concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfAnnotationsOverlapConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfAnnotationsOverlapConcernedPages(pdfRevision);
	}
	
	/**
	 * Returns a list of PDF visual difference concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfVisualDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfVisualDifferenceConcernedPages(pdfRevision);
	}

	/**
	 * Returns a list of pages missing/added to the final revision in a comparison with a signed one
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfPageDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfPageDifferenceConcernedPages(pdfRevision);
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
		return timestamp.getSignerInformationStore();
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
