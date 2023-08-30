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
package eu.europa.esig.dss.detailedreport;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlChainItem;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalDataTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessEvidenceRecord;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualificationAtTime;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.jaxb.object.Message;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

/**
 * This class represents the detailed report built during the validation process. It contains information on each
 * executed constraint. It is composed among other of the
 * following building blocks:<br>
 * - Identification of the Signer's Certificate (ISC)<br>
 * - Validation Context Initialization (VCI)<br>
 * - X.509 Certificate Validation (XCV)<br>
 * - Cryptographic Verification (CV)<br>
 * - Signature Acceptance Validation (SAV)<br>
 * - Basic Validation Process<br>
 * - Validation Process for Time-Stamps<br>
 * - Validation Process for AdES-T<br>
 * - Validation of LTV forms<br>
 */
public class DetailedReport {

	/**
	 * The JAXB Detailed report
	 */
	private final XmlDetailedReport jaxbDetailedReport;

	/**
	 * Collects messages of the validation process
	 */
	private DetailedReportMessageCollector messageCollector;

	/**
	 * The default constructor
	 *
	 * @param jaxbDetailedReport {@link XmlDetailedReport}
	 */
	public DetailedReport(XmlDetailedReport jaxbDetailedReport) {
		this.jaxbDetailedReport = jaxbDetailedReport;
	}

	/**
	 * This method returns the result of the Basic Building Block for a token (signature, timestamp, revocation)
	 * 
	 * @param tokenId
	 *            the token identifier
	 * @return the Indication
	 */
	public Indication getBasicBuildingBlocksIndication(String tokenId) {
		XmlBasicBuildingBlocks bbb = getBasicBuildingBlockById(tokenId);
		if (bbb != null) {
			return bbb.getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * This method returns the result of the Basic Building Block for a token (signature, timestamp, revocation)
	 * 
	 * @param tokenId
	 *            the token identifier
	 * @return the SubIndication
	 */
	public SubIndication getBasicBuildingBlocksSubIndication(String tokenId) {
		XmlBasicBuildingBlocks bbb = getBasicBuildingBlockById(tokenId);
		if (bbb != null) {
			return bbb.getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Returns a list of certificate token ids representing the certificate chain of the token in question
	 *
	 * @param tokenId {@link String} id of a token to get certificate chain for
	 * @return a list of {@link String} ids
	 */
	public List<String> getBasicBuildingBlocksCertChain(String tokenId) {
		List<String> certIds = new LinkedList<>();
		XmlBasicBuildingBlocks bbb = getBasicBuildingBlockById(tokenId);
		if (bbb != null) {
			List<XmlChainItem> chainItems = bbb.getCertificateChain().getChainItem();
			if (chainItems != null) {
				for (XmlChainItem chainItem : chainItems) {
					certIds.add(chainItem.getId());
				}
			}
		}
		return certIds;
	}

	/**
	 * This method returns the full content of the Basic Building Block for a token (signature, timestamp, revocation)
	 * 
	 * @param tokenId
	 *            the token identifier
	 * @return the XmlBasicBuildingBlocks
	 */
	public XmlBasicBuildingBlocks getBasicBuildingBlockById(String tokenId) {
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		if (basicBuildingBlocks != null) {
			for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
				if (tokenId.equals(xmlBasicBuildingBlocks.getId())) {
					return xmlBasicBuildingBlocks;
				}
			}
		}
		return null;
	}

	/**
	 * Returns the number of Basic Building Blocks.
	 *
	 * @return {@code int} number of Basic Building Blocks
	 */
	public int getBasicBuildingBlocksNumber() {
		return jaxbDetailedReport.getBasicBuildingBlocks().size();
	}

	/**
	 * Returns the id of the token. The signature is identified by its index: 0 for the first one.
	 *
	 * @param index
	 *            (position/order) of the signature within the report
	 * @return {@code String} identifying the token
	 */
	public String getBasicBuildingBlocksSignatureId(final int index) {
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		if (bbbs != null && (bbbs.size() >= index)) {
			XmlBasicBuildingBlocks bbb = jaxbDetailedReport.getBasicBuildingBlocks().get(index);
			if (bbb != null) {
				return bbb.getId();
			}
		}
		return null;
	}

	/**
	 * Returns a list of all signature ids
	 *
	 * @return a list of {@link String} ids
	 */
	public List<String> getSignatureIds() {
		List<String> result = new ArrayList<>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.SIGNATURE == bbb.getType() || Context.COUNTER_SIGNATURE == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return the first signature id
	 */
	public String getFirstSignatureId() {
		List<String> signatureIdList = getSignatureIds();
		if (!signatureIdList.isEmpty()) {
			return signatureIdList.get(0);
		}
		return null;
	}

	/**
	 * This method returns the first timestamp id.
	 *
	 * @return the first timestamp id
	 */
	public String getFirstTimestampId() {
		final List<String> timestampIdList = getTimestampIds();
		if (!timestampIdList.isEmpty()) {
			return timestampIdList.get(0);
		}
		return null;
	}

	/**
	 * Returns a list of all timestamp ids
	 *
	 * @return a list of {@link String} ids
	 */
	public List<String> getTimestampIds() {
		List<String> result = new ArrayList<>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.TIMESTAMP == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	/**
	 * This method returns the first evidence record id.
	 *
	 * @return the first evidence record id
	 */
	public String getFirstEvidenceRecordId() {
		final List<String> evidenceRecordIds = getEvidenceRecordIds();
		if (!evidenceRecordIds.isEmpty()) {
			return evidenceRecordIds.get(0);
		}
		return null;
	}

	/**
	 * Returns a list of all evidence record ids
	 *
	 * @return a list of {@link String} ids
	 */
	public List<String> getEvidenceRecordIds() {
		List<String> result = new ArrayList<>();
		List<?> tokens = jaxbDetailedReport.getSignatureOrTimestampOrEvidenceRecord();
		for (Object token : tokens) {
			if (token instanceof XmlEvidenceRecord) {
				XmlEvidenceRecord xmlEvidenceRecord = (XmlEvidenceRecord) token;
				result.add(xmlEvidenceRecord.getId());
			} else if (token instanceof XmlSignature) {
				XmlSignature xmlSignature = (XmlSignature) token;
				List<XmlEvidenceRecord> evidenceRecords = xmlSignature.getEvidenceRecords();
				for (XmlEvidenceRecord xmlEvidenceRecord : evidenceRecords) {
					result.add(xmlEvidenceRecord.getId());
				}
			}
		}
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.TIMESTAMP == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	/**
	 * Returns a list of all revocation data ids
	 *
	 * @return a list of {@link String} ids
	 */
	public List<String> getRevocationIds() {
		List<String> result = new ArrayList<>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.REVOCATION == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	/**
	 * Returns best-signature-time for the signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link Date}
	 */
	public Date getBestSignatureTime(String signatureId) {
		XmlProofOfExistence proofOfExistence = getBestProofOfExistence(signatureId);
		if (proofOfExistence != null) {
			return proofOfExistence.getTime();
		}
		return null;
	}

	/**
	 * Gets best proof-of-existence for the signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link XmlProofOfExistence}
	 */
	public XmlProofOfExistence getBestProofOfExistence(String signatureId) {
		XmlSignature xmlSignature = getXmlSignatureById(signatureId);
		if (xmlSignature != null) {
			if (xmlSignature.getValidationProcessArchivalData() != null) {
				return xmlSignature.getValidationProcessArchivalData().getProofOfExistence();
			}
			if (xmlSignature.getValidationProcessLongTermData() != null) {
				return xmlSignature.getValidationProcessLongTermData().getProofOfExistence();
			}
			if (xmlSignature.getValidationProcessBasicSignature() != null) {
				return xmlSignature.getValidationProcessBasicSignature().getProofOfExistence();
			}
		}
		return null;
	}

	/**
	 * Returns lowest POE of the evidence record with the given Id
	 *
	 * @param evidenceRecordId {@link String} id of the evidence record to get POE for
	 * @return {@link Date}
	 */
	public Date getEvidenceRecordLowestPOETime(String evidenceRecordId) {
		XmlEvidenceRecord xmlEvidenceRecord = getXmlEvidenceRecordById(evidenceRecordId);
		if (xmlEvidenceRecord != null) {
			if (xmlEvidenceRecord.getValidationProcessEvidenceRecord() != null) {
				XmlProofOfExistence poe = xmlEvidenceRecord.getValidationProcessEvidenceRecord().getProofOfExistence();
				if (poe != null) {
					return poe.getTime();
				}
			}
		}
		return null;
	}

	/**
	 * Gets basic validation indication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getBasicValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessBasicSignature() != null
				&& signature.getValidationProcessBasicSignature().getConclusion() != null) {
			return signature.getValidationProcessBasicSignature().getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets basic validation subIndication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link SubIndication}
	 */
	public SubIndication getBasicValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessBasicSignature() != null
				&& signature.getValidationProcessBasicSignature().getConclusion() != null) {
			return signature.getValidationProcessBasicSignature().getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Gets timestamp basic validation indication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getBasicTimestampValidationIndication(String timestampId) {
		XmlValidationProcessBasicTimestamp timestampValidationById = getBasicTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets timestamp basic validation subIndication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public SubIndication getBasicTimestampValidationSubIndication(String timestampId) {
		XmlValidationProcessBasicTimestamp timestampValidationById = getBasicTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Gets timestamp validation indication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 * @deprecated since DSS 5.13. Use {@code #getBasicTimestampValidationIndication(timestampId)} instead
	 */
	@Deprecated
	public Indication getTimestampValidationIndication(String timestampId) {
		return getBasicTimestampValidationIndication(timestampId);
	}

	/**
	 * Gets timestamp validation subIndication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 * @deprecated since DSS 5.13. Use {@code #getBasicTimestampValidationSubIndication(timestampId)} instead
	 */
	@Deprecated
	public SubIndication getTimestampValidationSubIndication(String timestampId) {
		return getBasicTimestampValidationSubIndication(timestampId);
	}

	/**
	 * Gets timestamp validation with archive data indication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getArchiveDataTimestampValidationIndication(String timestampId) {
		XmlValidationProcessArchivalDataTimestamp timestampValidationById = getArchiveDataTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets timestamp validation with archive data subIndication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link SubIndication}
	 */
	public SubIndication getArchiveDataTimestampValidationSubIndication(String timestampId) {
		XmlValidationProcessArchivalDataTimestamp timestampValidationById = getArchiveDataTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Gets evidence record validation indication for an evidence record with id
	 *
	 * @param evidenceRecordId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getEvidenceRecordValidationIndication(String evidenceRecordId) {
		XmlValidationProcessEvidenceRecord evidenceRecordValidationById = getEvidenceRecordValidationById(evidenceRecordId);
		if (evidenceRecordValidationById != null && evidenceRecordValidationById.getConclusion() != null) {
			return evidenceRecordValidationById.getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets evidence record validation subIndication for an evidence record with id
	 *
	 * @param evidenceRecordId {@link String}
	 * @return {@link SubIndication}
	 */
	public SubIndication getEvidenceRecordValidationSubIndication(String evidenceRecordId) {
		XmlValidationProcessEvidenceRecord evidenceRecordValidationById = getEvidenceRecordValidationById(evidenceRecordId);
		if (evidenceRecordValidationById != null && evidenceRecordValidationById.getConclusion() != null) {
			return evidenceRecordValidationById.getConclusion().getSubIndication();
		}
		return null;
	}

	private XmlValidationProcessEvidenceRecord getEvidenceRecordValidationById(String evidenceRecordId) {
		XmlEvidenceRecord evidenceRecord = getXmlEvidenceRecordById(evidenceRecordId);
		if (evidenceRecord != null) {
			return evidenceRecord.getValidationProcessEvidenceRecord();
		}
		return null;
	}

	/**
	 * Returns an {@code XmlEvidenceRecord} by the given id
	 * Null if the evidence record is not found
	 *
	 * @param evidenceRecordId {@link String} id of an evidence record to get
	 * @return {@link XmlEvidenceRecord}
	 */
	public XmlEvidenceRecord getXmlEvidenceRecordById(String evidenceRecordId) {
		for (XmlEvidenceRecord xmlEvidenceRecord : getIndependentEvidenceRecords()) {
			if (xmlEvidenceRecord.getId().equals(evidenceRecordId)) {
				return xmlEvidenceRecord;
			}
		}

		// TODO : extract evidence records from signatures
		return null;
	}

	/**
	 * Gets long-term validation indication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getLongTermValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessLongTermData() != null && signature.getValidationProcessLongTermData().getConclusion() != null) {
			return signature.getValidationProcessLongTermData().getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets long-term validation subIndication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public SubIndication getLongTermValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessLongTermData() != null && signature.getValidationProcessLongTermData().getConclusion() != null) {
			return signature.getValidationProcessLongTermData().getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Gets validation with archive data indication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getArchiveDataValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessArchivalData() != null && signature.getValidationProcessArchivalData().getConclusion() != null) {
			return signature.getValidationProcessArchivalData().getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets validation with archive data subIndication for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link SubIndication}
	 */
	public SubIndication getArchiveDataValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessArchivalData() != null && signature.getValidationProcessArchivalData().getConclusion() != null) {
			return signature.getValidationProcessArchivalData().getConclusion().getSubIndication();
		}
		return null;
	}

	/**
	 * Gets qualification for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return {@link SignatureQualification}
	 */
	public SignatureQualification getSignatureQualification(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationSignatureQualification() != null) {
			return signature.getValidationSignatureQualification().getSignatureQualification();
		}
		return null;
	}

	/**
	 * Gets the final qualification result for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link TimestampQualification}
	 */
	public TimestampQualification getTimestampQualification(String timestampId) {
		XmlValidationTimestampQualification timestampQualif = getXmlTimestampQualificationById(timestampId);
		if (timestampQualif !=null) {
			return timestampQualif.getTimestampQualification();
		}
		return null;
	}

	/**
	 * Gets qualification for a timestamp with the given id at the timestamp generation time
	 *
	 * @param timestampId {@link String}
	 * @return {@link TimestampQualification}
	 */
	public TimestampQualification getTimestampQualificationAtTstGenerationTime(String timestampId) {
		return getTimestampQualificationAtValidationTime(ValidationTime.TIMESTAMP_GENERATION_TIME, timestampId);
	}

	/**
	 * Gets qualification for a timestamp with the given id at its best available POE time
	 *
	 * @param timestampId {@link String}
	 * @return {@link TimestampQualification}
	 */
	public TimestampQualification getTimestampQualificationAtBestPoeTime(String timestampId) {
		return getTimestampQualificationAtValidationTime(ValidationTime.TIMESTAMP_POE_TIME, timestampId);
	}

	/**
	 * Gets qualification for a timestamp with the given id at the timestamp generation time
	 *
	 * @param timestampId {@link String}
	 * @return {@link TimestampQualification}
	 */
	private TimestampQualification getTimestampQualificationAtValidationTime(ValidationTime validationTime, String timestampId) {
		XmlValidationTimestampQualification tstQualificationValidation = getXmlTimestampQualificationById(timestampId);
		if (tstQualificationValidation != null) {
			for (XmlValidationTimestampQualificationAtTime tstQualAtTime : tstQualificationValidation.getValidationTimestampQualificationAtTime()) {
				if (validationTime == tstQualAtTime.getValidationTime()) {
					return tstQualAtTime.getTimestampQualification();
				}
			}
		}
		return null;
	}

	private XmlValidationTimestampQualification getXmlTimestampQualificationById(String timestampId) {
		XmlTimestamp timestamp = getXmlTimestampById(timestampId);
		if (timestamp != null) {
			return timestamp.getValidationTimestampQualification();
		}
		return null;
	}

	private XmlValidationProcessBasicTimestamp getBasicTimestampValidationById(String timestampId) {
		XmlTimestamp timestamp = getXmlTimestampById(timestampId);
		if (timestamp != null) {
			return timestamp.getValidationProcessBasicTimestamp();
		}
		return null;
	}

	private XmlValidationProcessArchivalDataTimestamp getArchiveDataTimestampValidationById(String timestampId) {
		XmlTimestamp timestamp = getXmlTimestampById(timestampId);
		if (timestamp != null) {
			return timestamp.getValidationProcessArchivalDataTimestamp();
		}
		return null;
	}

	/**
	 * Returns an {@code XmlTimestamp} by the given id
	 * Null if the timestamp is not found
	 * 
	 * @param timestampId {@link String} id of a timestamp to get
	 * @return {@link XmlTimestamp}
	 */
	public XmlTimestamp getXmlTimestampById(String timestampId) {
		for (XmlTimestamp xmlTimestamp : getIndependentTimestamps()) {
			if (xmlTimestamp.getId().equals(timestampId)) {
				return xmlTimestamp;
			}
		}

		List<XmlSignature> signatures = getSignatures();
		for (XmlSignature xmlSignature : signatures) {
			List<XmlTimestamp> timestamps = xmlSignature.getTimestamps();
			for (XmlTimestamp xmlTimestamp : timestamps) {
				if (xmlTimestamp.getId().equals(timestampId)) {
					return xmlTimestamp;
				}
			}
			// TODO : handle embedded evidence record timestamps
		}

		List<XmlEvidenceRecord> independentEvidenceRecords = getIndependentEvidenceRecords();
		for (XmlEvidenceRecord xmlEvidenceRecord : independentEvidenceRecords) {
			List<XmlTimestamp> timestamps = xmlEvidenceRecord.getTimestamps();
			for (XmlTimestamp xmlTimestamp : timestamps) {
				if (xmlTimestamp.getId().equals(timestampId)) {
					return xmlTimestamp;
				}
			}
		}
		return null;
	}

	/**
	 * Returns an {@code XmlSignature} by the given id
	 * Null if the signature is not found
	 * 
	 * @param signatureId {@link String} id of a signature to get
	 * @return {@link XmlSignature}
	 */
	public XmlSignature getXmlSignatureById(String signatureId) {
		List<XmlSignature> signatures = getSignatures();
		if (signatures != null) {
			for (XmlSignature xmlSignature : signatures) {
				if (signatureId.equals(xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	/**
	 * Returns an {@code XmlCertificate} by id if exists, null otherwise
	 * NOTE: should be used only for certificate validation process
	 * 
	 * @param certificateId id of a certificate to extract
	 * @return {@link XmlCertificate}
	 */
	public XmlCertificate getXmlCertificateById(String certificateId) {
		List<XmlCertificate> certificates = getCertificates();
		if (certificates != null) {
			for (XmlCertificate xmlCertificate : certificates) {
				if (certificateId.equals(xmlCertificate.getId())) {
					return xmlCertificate;
				}
			}
		}
		return null;
	}

	/**
	 * Returns a list of all signatures
	 *
	 * @return a list of {@link XmlSignature}s
	 */
	public List<XmlSignature> getSignatures() {
		List<XmlSignature> result = new ArrayList<>();
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (element instanceof XmlSignature) {
				result.add((XmlSignature) element);
			}
		}
		return result;
	}

	/**
	 * Returns a list of all independent (detached) timestamps
	 *
	 * @return a list of {@link XmlTimestamp}s
	 */
	public List<XmlTimestamp> getIndependentTimestamps() {
		List<XmlTimestamp> result = new ArrayList<>();
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (element instanceof XmlTimestamp) {
				result.add((XmlTimestamp) element);
			}
		}
		return result;
	}

	/**
	 * Returns a list of all independent (detached) evidence records
	 *
	 * @return a list of {@link XmlEvidenceRecord}s
	 */
	public List<XmlEvidenceRecord> getIndependentEvidenceRecords() {
		List<XmlEvidenceRecord> result = new ArrayList<>();
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (element instanceof XmlEvidenceRecord) {
				result.add((XmlEvidenceRecord) element);
			}
		}
		return result;
	}

	/**
	 * Returns a list of processed {@link XmlCertificate}s
	 * NOTE: the method returns not empty list only for certificate validation process
	 * 
	 * @return list of {@link XmlCertificate}s
	 */
	public List<XmlCertificate> getCertificates() {
		List<XmlCertificate> result = new ArrayList<>();
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrEvidenceRecord()) {
			if (element instanceof XmlCertificate) {
				result.add((XmlCertificate) element);
			}
		}
		return result;
	}

	/**
	 * This method returns a complete block of a TL validation
	 * 
	 * @param tlId
	 *            the LOTL/TL identifier
	 * @return XmlTLAnalysis
	 */
	public XmlTLAnalysis getTLAnalysisById(String tlId) {
		List<XmlTLAnalysis> tlAnalysisBlocks = jaxbDetailedReport.getTLAnalysis();
		if (tlAnalysisBlocks != null) {
			for (XmlTLAnalysis xmlTLAnalysis : tlAnalysisBlocks) {
				if (tlId.equals(xmlTLAnalysis.getId())) {
					return xmlTLAnalysis;
				}
			}
		}
		return null;
	}

	/**
	 * Returns the JAXB Detailed Report
	 *
	 * @return {@link XmlDetailedReport}
	 */
	public XmlDetailedReport getJAXBModel() {
		return jaxbDetailedReport;
	}

	/**
	 * Returns if the certificate validation has been performed
	 * (therefore the certificate corresponding data can be retrieved)
	 *
	 * @return if the certificate validation has been performed
	 */
	public boolean isCertificateValidation() {
		List<XmlCertificate> certificates = getCertificates();
		return certificates != null && !certificates.isEmpty();
	}

	/**
	 * Gets the qualification for certificate with id at its issuance time
	 *
	 * @param certificateId {@link String}
	 * @return {@link CertificateQualification}
	 */
	public CertificateQualification getCertificateQualificationAtIssuance(String certificateId) {
		return getCertificateQualificationAtTime(ValidationTime.CERTIFICATE_ISSUANCE_TIME, certificateId);
	}

	/**
	 * Gets the qualification for certificate with id at the validation time
	 *
	 * @param certificateId {@link String}
	 * @return {@link CertificateQualification}
	 */
	public CertificateQualification getCertificateQualificationAtValidation(String certificateId) {
		return getCertificateQualificationAtTime(ValidationTime.VALIDATION_TIME, certificateId);
	}

	private CertificateQualification getCertificateQualificationAtTime(ValidationTime validationTime, String certificateId) {
		XmlCertificate certificate = getXmlCertificateById(certificateId);
		if (certificate != null) {
			List<XmlValidationCertificateQualification> validationCertificateQualifications = certificate.getValidationCertificateQualification();
			if (validationCertificateQualifications != null) {
				for (XmlValidationCertificateQualification validationCertificateQualification : validationCertificateQualifications) {
					if (validationTime == validationCertificateQualification.getValidationTime()) {
						return validationCertificateQualification.getCertificateQualification();
					}
				}
			}
		}
		return CertificateQualification.NA;
	}

	/**
	 * Gets XCV building block conclusion for a certificate with id
	 *
	 * @param certificateId {@link String}
	 * @return {@link XmlConclusion}
	 */
	public XmlConclusion getCertificateXCVConclusion(String certificateId) {
		List<XmlCertificate> certificates = getCertificates();
		if (certificates == null || certificates.isEmpty()) {
			throw new UnsupportedOperationException("Only supported in report for certificate");
		}
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
			XmlXCV xcv = xmlBasicBuildingBlocks.getXCV();
			if (xcv != null) {
				boolean trustAnchorReached = false;
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				for (XmlSubXCV xmlSubXCV : subXCV) {
					if (xmlSubXCV.isTrustAnchor() != null && xmlSubXCV.isTrustAnchor()) {
						trustAnchorReached = true;
					}
					if (certificateId.equals(xmlSubXCV.getId())) {
						return xmlSubXCV.getConclusion();
					}
				}
				if (trustAnchorReached) {
					XmlConclusion xmlConclusion = new XmlConclusion();
					xmlConclusion.setIndication(Indication.PASSED);
					return xmlConclusion;
				} else {
					// if {@link SubX509CertificateValidation} is not executed and
					// the certificate is in untrusted chain, return global XmlConclusion
					return xcv.getConclusion();
				}
			}
		}
		return null;
	}

	/**
	 * Returns the final validation conclusion for a token with a given Id
	 *
	 * @param tokenId {@link String} of a token to get the final validation conclusion result for
	 * @return {@link XmlConclusion}
	 */
	public XmlConclusion getFinalConclusion(String tokenId) {
		XmlSignature signatureById = getXmlSignatureById(tokenId);
		if (signatureById != null) {
			return signatureById.getConclusion();
		}
		XmlTimestamp timestampById = getXmlTimestampById(tokenId);
		if (timestampById != null) {
			return timestampById.getConclusion();
		}
		XmlEvidenceRecord evidenceRecordById = getXmlEvidenceRecordById(tokenId);
		if (evidenceRecordById != null) {
			return evidenceRecordById.getConclusion();
		}
		XmlBasicBuildingBlocks bbb = getBasicBuildingBlockById(tokenId);
		if (bbb != null) {
			return bbb.getConclusion();
		}
		return null;
	}

	/**
	 * Gets the validation indication to a token with id
	 * corresponding to the highest validation level
	 *
	 * @param tokenId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getFinalIndication(String tokenId) {
		XmlConclusion finalConclusion = getFinalConclusion(tokenId);
		if (finalConclusion != null) {
			return finalConclusion.getIndication();
		}
		return null;
	}

	/**
	 * Gets the validation subIndication to a token with id
	 * corresponding to the highest validation level
	 *
	 * @param tokenId {@link String}
	 * @return {@link Indication}
	 */
	public SubIndication getFinalSubIndication(String tokenId) {
		XmlConclusion finalConclusion = getFinalConclusion(tokenId);
		if (finalConclusion != null) {
			return finalConclusion.getSubIndication();
		}
		return null;
	}

	/**
	 * Gets the validation conclusion to a signature with id corresponding to the highest validation level
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public XmlConstraintsConclusion getHighestConclusion(String signatureId) {
		XmlSignature xmlSignature = getXmlSignatureById(signatureId);
		if (xmlSignature.getValidationProcessArchivalData() != null) {
			return xmlSignature.getValidationProcessArchivalData();
		} else if (xmlSignature.getValidationProcessLongTermData() != null) {
			return xmlSignature.getValidationProcessLongTermData();
		} else {
			return xmlSignature.getValidationProcessBasicSignature();
		}
	}

	/**
	 * Gets signing certificate validation block for the given BasicBuildingBlock
	 *
	 * @param bbbId {@link String} BBB's id
	 * @return {@link XmlSubXCV}
	 */
	public XmlSubXCV getSigningCertificate(String bbbId) {
		XmlBasicBuildingBlocks basicBuildingBlocks = getBasicBuildingBlockById(bbbId);
		if (basicBuildingBlocks != null) {
			XmlXCV xcv = basicBuildingBlocks.getXCV();
			if (xcv != null) {
				List<XmlSubXCV> subXCVs = xcv.getSubXCV();
				if (subXCVs != null && !subXCVs.isEmpty()) {
					return subXCVs.get(0);
				}
			}
		}
		return null;
	}

	/**
	 * Gets the used {@code DetailedReportMessageCollector}
	 *
	 * @return {@link DetailedReportMessageCollector}
	 */
	DetailedReportMessageCollector getMessageCollector() {
		if (messageCollector == null) {
			messageCollector = new DetailedReportMessageCollector(this);
		}
		return messageCollector;
	}

	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation error messages for a token with the given id
	 *
	 * @param tokenId {@link String}
	 * @return a list of error {@link Message}s
	 */
    public List<Message> getAdESValidationErrors(String tokenId) {
    	return getMessageCollector().getAdESValidationErrors(tokenId);
    }

	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation warning messages for a token with the given id
	 *
	 * @param tokenId {@link String}
	 * @return a list of warning {@link Message}s
	 */
    public List<Message> getAdESValidationWarnings(String tokenId) {
    	return getMessageCollector().getAdESValidationWarnings(tokenId);
    }

	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation info messages for a token with the given id
	 *
	 * @param tokenId {@link String}
	 * @return a list of info {@link Message}s
	 */
    public List<Message> getAdESValidationInfos(String tokenId) {
    	return getMessageCollector().getAdESValidationInfos(tokenId);
    }

	/**
	 * Returns a list of qualification validation errors for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification errors for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getQualificationErrors(String tokenId) {
		return getMessageCollector().getQualificationErrors(tokenId);
	}

	/**
	 * Returns a list of qualification validation warnings for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getQualificationWarnings(String tokenId) {
		return getMessageCollector().getQualificationWarnings(tokenId);
	}

	/**
	 * Returns a list of qualification validation infos for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification infos for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getQualificationInfos(String tokenId) {
		return getMessageCollector().getQualificationInfos(tokenId);
	}

	/**
	 * Returns a list of qualification validation errors for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification errors for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationErrorsAtIssuanceTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationErrorsAtIssuanceTime(certificateId);
	}

	/**
	 * Returns a list of qualification validation warnings for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationWarningsAtIssuanceTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationWarningsAtIssuanceTime(certificateId);
	}

	/**
	 * Returns a list of qualification validation information messages for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification information messages for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationInfosAtIssuanceTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationInfosAtIssuanceTime(certificateId);
	}

	/**
	 * Returns a list of qualification validation errors for a certificate with the given id at validation time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification errors for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationErrorsAtValidationTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationErrorsAtValidationTime(certificateId);
	}

	/**
	 * Returns a list of qualification validation warnings for a certificate with the given id at validation time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationWarningsAtValidationTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationWarningsAtValidationTime(certificateId);
	}

	/**
	 * Returns a list of qualification validation information messages for a certificate with the given id at validation time
	 * NOTE: applicable only on certificate validation (see {@code eu.europa.esig.dss.validation.CertificateValidator})
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification information messages for
	 * @return a list of {@link Message}s
	 */
	public List<Message> getCertificateQualificationInfosAtValidationTime(String certificateId) {
		return getMessageCollector().getCertificateQualificationInfosAtValidationTime(certificateId);
	}

}
