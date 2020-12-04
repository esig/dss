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
import eu.europa.esig.dss.detailedreport.jaxb.XmlProofOfExistence;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.enumerations.ValidationTime;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

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
		List<String> result = getSignatureIds();
		if (result.size() > 0) {
			return result.get(0);
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
	 * Gets timestamp validation indication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getTimestampValidationIndication(String timestampId) {
		XmlValidationProcessTimestamp timestampValidationById = getTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getIndication();
		}
		return null;
	}

	/**
	 * Gets timestamp validation subIndication for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public SubIndication getTimestampValidationSubIndication(String timestampId) {
		XmlValidationProcessTimestamp timestampValidationById = getTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getSubIndication();
		}
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
	 * @return {@link Indication}
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
	 * @return {@link Indication}
	 */
	public SignatureQualification getSignatureQualification(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationSignatureQualification() != null) {
			return signature.getValidationSignatureQualification().getSignatureQualification();
		}
		return null;
	}

	/**
	 * Gets qualification for a timestamp with id
	 *
	 * @param timestampId {@link String}
	 * @return {@link Indication}
	 */
	public TimestampQualification getTimestampQualification(String timestampId) {
		XmlValidationTimestampQualification timestampQualif = getXmlTimestampQualificationById(timestampId);
		if (timestampQualif !=null) {
			return timestampQualif.getTimestampQualification();
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

	private XmlValidationProcessTimestamp getTimestampValidationById(String timestampId) {
		XmlTimestamp timestamp = getXmlTimestampById(timestampId);
		if (timestamp != null) {
			return timestamp.getValidationProcessTimestamp();
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
			List<XmlTimestamp> timestamps = xmlSignature.getTimestamp();
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
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrCertificate()) {
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
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrCertificate()) {
			if (element instanceof XmlTimestamp) {
				result.add((XmlTimestamp) element);
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
		for (Serializable element : jaxbDetailedReport.getSignatureOrTimestampOrCertificate()) {
			if (element instanceof XmlCertificate) {
				result.add((XmlCertificate) element);
			}
		}
		return result;
	}
	/**
	 * This method returns the a complete block of a TL validation
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
	 * Gets the qualification for certificate with id at its issuance time
	 *
	 * @param certificateId {@link String}
	 * @return {@link CertificateQualification}
	 */
	public CertificateQualification getCertificateQualificationAtIssuance(String certificateId) {
		return getCertificateQualification(ValidationTime.CERTIFICATE_ISSUANCE_TIME, certificateId);
	}

	/**
	 * Gets the qualification for certificate with id at the validation time
	 *
	 * @param certificateId {@link String}
	 * @return {@link CertificateQualification}
	 */
	public CertificateQualification getCertificateQualificationAtValidation(String certificateId) {
		return getCertificateQualification(ValidationTime.VALIDATION_TIME, certificateId);
	}

	private CertificateQualification getCertificateQualification(ValidationTime validationTime, String certificateId) {
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
		if (certificates == null || certificates.size() == 0) {
			throw new UnsupportedOperationException("Only supported in report for certificate");
		}
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
			XmlXCV xcv = xmlBasicBuildingBlocks.getXCV();
			if (xcv != null) {
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				for (XmlSubXCV xmlSubXCV : subXCV) {
					if (certificateId.equals(xmlSubXCV.getId())) {
						return xmlSubXCV.getConclusion();
					}
				}
				// if {@link SubX509CertificateValidation} is not executed, i.e. the certificate is in untrusted chain,
				// return global XmlConclusion
				return xcv.getConclusion();
			}
		}
		return null;
	}

	/**
	 * Gets the validation indication to a signature with id corresponding to the highest validation level
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public Indication getFinalIndication(String signatureId) {
		return getXmlSignatureById(signatureId).getConclusion().getIndication();
	}

	/**
	 * Gets the validation subIndication to a signature with id corresponding to the highest validation level
	 *
	 * @param signatureId {@link String}
	 * @return {@link Indication}
	 */
	public SubIndication getFinalSubIndication(String signatureId) {
		return getXmlSignatureById(signatureId).getConclusion().getSubIndication();
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
				if (subXCVs != null && subXCVs.size() > 0) {
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
	 * Returns a set of error messages for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return a set of {@link String} error messages
	 */
    public Set<String> getErrors(String signatureId) {
    	return getMessageCollector().getErrors(signatureId);
    }

	/**
	 * Returns a set of warning messages for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return a set of {@link String} warning messages
	 */
    public Set<String> getWarnings(String signatureId) {
    	return getMessageCollector().getWarnings(signatureId);
    }

	/**
	 * Returns a set of info messages for a signature with id
	 *
	 * @param signatureId {@link String}
	 * @return a set of {@link String} info messages
	 */
    public Set<String> getInfos(String signatureId) {
    	return getMessageCollector().getInfos(signatureId);
    }

}
