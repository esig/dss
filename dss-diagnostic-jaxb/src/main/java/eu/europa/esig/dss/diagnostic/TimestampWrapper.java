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

import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Provides a user-friendly interface for dealing with JAXB {@code XmlTimestamp} object
 */
public class TimestampWrapper extends AbstractSignatureWrapper {

	/** The wrapped XmlTimestamp */
	private final XmlTimestamp timestamp;
	
	/**
	 * Default constructor
	 *
	 * @param timestamp {@link XmlTimestamp}
	 */
	public TimestampWrapper(XmlTimestamp timestamp) {
		Objects.requireNonNull(timestamp, "XmlTimestamp cannot be null!");
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

	/**
	 * Checks if the time-stamp's Id is duplicated within the validating document
	 *
	 * @return TRUE if there is a duplicated time-stamp Id, FALSE otherwise
	 */
	public boolean isTimestampDuplicated() {
		return timestamp.isDuplicated() != null && timestamp.isDuplicated();
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

	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(timestamp.getFoundCertificates());
	}

	@Override
	public FoundRevocationsProxy foundRevocations() {
		return new FoundRevocationsProxy(timestamp.getFoundRevocations());
	}

	/**
	 * Returns a list of evidence records covering the time-stamp file (applicable for detached time-stamps only)
	 *
	 * @return a list of {@link EvidenceRecordWrapper}s
	 */
	public List<EvidenceRecordWrapper> getEvidenceRecords() {
		List<EvidenceRecordWrapper> result = new ArrayList<>();
		List<XmlFoundEvidenceRecord> foundEvidenceRecords = timestamp.getFoundEvidenceRecords();
		for (XmlFoundEvidenceRecord xmlEvidenceRecord : foundEvidenceRecords) {
			result.add(new EvidenceRecordWrapper(xmlEvidenceRecord.getEvidenceRecord()));
		}
		return result;
	}

	/**
	 * Returns a list of associated evidence record identifiers
	 *
	 * @return a list of {@link String}
	 */
	public List<String> getEvidenceRecordIdsList() {
		List<String> result = new ArrayList<>();
		for (EvidenceRecordWrapper evidenceRecordWrapper : getEvidenceRecords()) {
			result.add(evidenceRecordWrapper.getId());
		}
		return result;
	}

	/**
	 * Returns identifiers of all covering evidence record time-stamps
	 *
	 * @return a list of {@link String} time-stamp identifiers
	 */
	public List<String> getEvidenceRecordTimestampIds() {
		List<String> result = new ArrayList<>();
		for (EvidenceRecordWrapper evidenceRecordWrapper : getEvidenceRecords()) {
			result.addAll(evidenceRecordWrapper.getTimestampIdsList());
		}
		return result;
	}

	/**
	 * Returns the type of the timestamp
	 *
	 * @return {@link TimestampType}
	 */
	public TimestampType getType() {
		return timestamp.getType();
	}
	
	/**
	 * Returns archive timestamp type, if applicable
	 * NOTE: returns null for non archive timestamps
	 *
	 * @return {@link ArchiveTimestampType}
	 */
	public ArchiveTimestampType getArchiveTimestampType() {
		return timestamp.getArchiveTimestampType();
	}

	/**
	 * Returns an evidence record archive timestamp type, if applicable
	 * NOTE: returns null for non evidence record archive timestamps
	 *
	 * @return {@link eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType}
	 */
	public EvidenceRecordTimestampType getEvidenceRecordTimestampType() {
		return timestamp.getEvidenceRecordTimestampType();
	}

	/**
	 * Returns the indicated production time of the timestamp
	 *
	 * @return {@link Date}
	 */
	public Date getProductionTime() {
		return timestamp.getProductionTime();
	}

	/**
	 * Returns message-imprint {@code XmlDigestMatcher}
	 *
	 * @return {@link XmlDigestMatcher}
	 */
	public XmlDigestMatcher getMessageImprint() {
		for (XmlDigestMatcher digestMatcher : getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
				return digestMatcher;
			}
		}
		return null;
	}

	/**
	 * Indicates if the message-imprint is found (all the required data for message-imprint computation is present)
	 *
	 * @return TRUE if the message-imprint data is found, FALSE otherwise
	 */
	public boolean isMessageImprintDataFound() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataFound();
		}
		return false;
	}

	/**
	 * Indicates if the message-imprint is intact (matches the computed message-imprint)
	 *
	 * @return TRUE if the message-imprint data is intact, FALSE otherwise
	 */
	public boolean isMessageImprintDataIntact() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataIntact();
		}
		return false;
	}

	/**
	 * Gets name of the timestamp file, when applicable
	 *
	 * @return {@link String} file name
	 */
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
	 * Returns a list of evidence records covered be the current timestamp
	 *
	 * @return list of {@link EvidenceRecordWrapper}s
	 */
	public List<EvidenceRecordWrapper> getTimestampedEvidenceRecords() {
		List<EvidenceRecordWrapper> evidenceRecords = new ArrayList<>();

		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.EVIDENCE_RECORD);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlEvidenceRecord) {
				evidenceRecords.add(new EvidenceRecordWrapper((XmlEvidenceRecord) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.EVIDENCE_RECORD));
			}
		}
		return evidenceRecords;
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

	/**
	 * Indicates if the signing certificate reference is present within the timestamp token and
	 * matches the actual signing certificate
	 *
	 * @return TRUE if the signing certificate is unambiguously identified, FALSE otherwise
	 */
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
	@SuppressWarnings("rawtypes")
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
	public List<OrphanCertificateTokenWrapper> getTimestampedOrphanCertificates() {
		List<OrphanCertificateTokenWrapper> orphanCertificates = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanCertificateToken) {
				orphanCertificates.add(new OrphanCertificateTokenWrapper((XmlOrphanCertificateToken) token));
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
	public List<OrphanRevocationTokenWrapper> getTimestampedOrphanRevocations() {
		List<OrphanRevocationTokenWrapper> orphanRevocations = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_REVOCATION);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanRevocationToken) {
				orphanRevocations.add(new OrphanRevocationTokenWrapper((XmlOrphanRevocationToken) token));
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

	/**
	 * Returns digest algorithm and value of the timestamp token binaries, when defined
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return timestamp.getDigestAlgoAndValue();
	}
	
	/* -------- PAdES RFC3161 Specific parameters --------- */

	/**
	 * Returns a PAdES-specific PDF Revision info
	 * NOTE: applicable only for PDF Document Timestamp
	 *
	 * @return {@link PDFRevisionWrapper}
	 */
	public PDFRevisionWrapper getPDFRevision() {
		if (timestamp.getPDFRevision() != null) {
			return new PDFRevisionWrapper(timestamp.getPDFRevision());
		}
		return null;
	}
	
	/**
	 * Returns a list if Signer Infos (Signer Information Store) from CAdES CMS Signed Data
	 * 
	 * @return list of {@link XmlSignerInfo}s
	 */
	public List<XmlSignerInfo> getSignatureInformationStore() {
		return timestamp.getSignerInformationStore();
	}

	/**
	 * Checks if the tsa field of TSTInfo is present
	 *
	 * @return TRUE if the TSTInfo.tsa is present, FALSE otherwise
	 */
	public boolean isTSAGeneralNamePresent() {
		return timestamp.getTSAGeneralName() != null;
	}

	/**
	 * Get TSA General Name value
	 *
	 * @return {@link String} representing a TSTInfo.tsa field when present, null otherwise
	 */
	public String getTSAGeneralNameValue() {
		if (isTSAGeneralNamePresent()) {
			return timestamp.getTSAGeneralName().getValue();
		}
		return null;
	}

	/**
	 * Checks if the content of TSTInfo.tsa field matches the timestamp's issuer distinguishing name,
	 * without taking order into account
	 *
	 * @return TRUE if the TSTInfo.tsa field value matches the timestamp's issuer name, FALSE otherwise
	 */
	public boolean isTSAGeneralNameMatch() {
		return isTSAGeneralNamePresent() && timestamp.getTSAGeneralName().isContentMatch();
	}

	/**
	 * Checks if the content and the order of TSTInfo.tsa field match the timestamp's issuer distinguishing name
	 *
	 * @return TRUE if the TSTInfo.tsa field value and order match the timestamp's issuer name, FALSE otherwise
	 */
	public boolean isTSAGeneralNameOrderMatch() {
		return isTSAGeneralNamePresent() && timestamp.getTSAGeneralName().isOrderMatch();
	}

	/**
	 * Returns Timestamp's Signature Scopes
	 *
	 * @return a list of {@link XmlSignatureScope}s
	 */
	public List<XmlSignatureScope> getTimestampScopes() {
		return timestamp.getTimestampScopes();
	}

}
