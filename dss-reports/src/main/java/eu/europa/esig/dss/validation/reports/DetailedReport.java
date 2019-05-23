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
package eu.europa.esig.dss.validation.reports;

import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCertificate;
import eu.europa.esig.dss.jaxb.detailedreport.XmlChainItem;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationCertificateQualification;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationSignatureQualification;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.ValidationTime;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

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

	private final eu.europa.esig.dss.jaxb.detailedreport.DetailedReport jaxbDetailedReport;

	public DetailedReport(eu.europa.esig.dss.jaxb.detailedreport.DetailedReport jaxbDetailedReport) {
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

	public List<String> getBasicBuildingBlocksCertChain(String tokenId) {
		List<String> certIds = new LinkedList<String>();
		XmlBasicBuildingBlocks bbb = getBasicBuildingBlockById(tokenId);
		if (bbb != null) {
			List<XmlChainItem> chainItems = bbb.getCertificateChain().getChainItem();
			if (Utils.isCollectionNotEmpty(chainItems)) {
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
		if (Utils.isCollectionNotEmpty(basicBuildingBlocks)) {
			for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
				if (Utils.areStringsEqual(xmlBasicBuildingBlocks.getId(), tokenId)) {
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
		if (Utils.collectionSize(bbbs) >= index) {
			XmlBasicBuildingBlocks bbb = jaxbDetailedReport.getBasicBuildingBlocks().get(index);
			if (bbb != null) {
				return bbb.getId();
			}
		}
		return null;
	}

	public List<String> getSignatureIds() {
		List<String> result = new ArrayList<String>();
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

	public List<String> getTimestampIds() {
		List<String> result = new ArrayList<String>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.TIMESTAMP == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	public List<String> getRevocationIds() {
		List<String> result = new ArrayList<String>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (Context.REVOCATION == bbb.getType()) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	public Date getBestSignatureTime(String signatureId) {
		XmlSignature xmlSignature = getXmlSignatureById(signatureId);
		if (xmlSignature != null) {
			if (xmlSignature.getValidationProcessArchivalData() != null && xmlSignature.getValidationProcessArchivalData().getBestSignatureTime() != null) {
				return xmlSignature.getValidationProcessArchivalData().getBestSignatureTime();
			}
			if (xmlSignature.getValidationProcessLongTermData() != null && xmlSignature.getValidationProcessLongTermData().getBestSignatureTime() != null) {
				return xmlSignature.getValidationProcessLongTermData().getBestSignatureTime();
			}
			if (xmlSignature.getValidationProcessBasicSignatures() != null
					&& xmlSignature.getValidationProcessBasicSignatures().getBestSignatureTime() != null) {
				return xmlSignature.getValidationProcessBasicSignatures().getBestSignatureTime();
			}
		}
		return null;
	}

	public Indication getBasicValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessBasicSignatures() != null
				&& signature.getValidationProcessBasicSignatures().getConclusion() != null) {
			return signature.getValidationProcessBasicSignatures().getConclusion().getIndication();
		}
		return null;
	}

	public SubIndication getBasicValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessBasicSignatures() != null
				&& signature.getValidationProcessBasicSignatures().getConclusion() != null) {
			return signature.getValidationProcessBasicSignatures().getConclusion().getSubIndication();
		}
		return null;
	}

	public Indication getTimestampValidationIndication(String timestampId) {
		XmlValidationProcessTimestamps timestampValidationById = getTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getIndication();
		}
		return null;
	}

	public SubIndication getTimestampValidationSubIndication(String timestampId) {
		XmlValidationProcessTimestamps timestampValidationById = getTimestampValidationById(timestampId);
		if (timestampValidationById != null && timestampValidationById.getConclusion() != null) {
			return timestampValidationById.getConclusion().getSubIndication();
		}
		return null;
	}

	public Indication getLongTermValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessLongTermData() != null && signature.getValidationProcessLongTermData().getConclusion() != null) {
			return signature.getValidationProcessLongTermData().getConclusion().getIndication();
		}
		return null;
	}

	public SubIndication getLongTermValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessLongTermData() != null && signature.getValidationProcessLongTermData().getConclusion() != null) {
			return signature.getValidationProcessLongTermData().getConclusion().getSubIndication();
		}
		return null;
	}

	public Indication getArchiveDataValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessArchivalData() != null && signature.getValidationProcessArchivalData().getConclusion() != null) {
			return signature.getValidationProcessArchivalData().getConclusion().getIndication();
		}
		return null;
	}

	public SubIndication getArchiveDataValidationSubIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessArchivalData() != null && signature.getValidationProcessArchivalData().getConclusion() != null) {
			return signature.getValidationProcessArchivalData().getConclusion().getSubIndication();
		}
		return null;
	}

	public SignatureQualification getSignatureQualification(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationSignatureQualification() != null) {
			return signature.getValidationSignatureQualification().getSignatureQualification();
		}
		return null;
	}

	public XmlSignature getXmlSignatureById(String signatureId) {
		List<XmlSignature> signatures = jaxbDetailedReport.getSignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	private XmlValidationProcessTimestamps getTimestampValidationById(String timestampId) {
		List<XmlSignature> signatures = jaxbDetailedReport.getSignatures();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				List<XmlValidationProcessTimestamps> validationTimestamps = xmlSignature.getValidationProcessTimestamps();
				if (Utils.isCollectionNotEmpty(validationTimestamps)) {
					for (XmlValidationProcessTimestamps tspValidation : validationTimestamps) {
						if (Utils.areStringsEqual(tspValidation.getId(), timestampId)) {
							return tspValidation;
						}
					}
				}
			}
		}
		return null;
	}

	public eu.europa.esig.dss.jaxb.detailedreport.DetailedReport getJAXBModel() {
		return jaxbDetailedReport;
	}

	public CertificateQualification getCertificateQualificationAtIssuance() {
		return getCertificateQualification(ValidationTime.CERTIFICATE_ISSUANCE_TIME);
	}

	public CertificateQualification getCertificateQualificationAtValidation() {
		return getCertificateQualification(ValidationTime.VALIDATION_TIME);
	}

	private CertificateQualification getCertificateQualification(ValidationTime validationTime) {
		XmlCertificate certificate = jaxbDetailedReport.getCertificate();
		if (certificate != null) {
			List<XmlValidationCertificateQualification> validationCertificateQualifications = certificate.getValidationCertificateQualification();
			if (Utils.isCollectionNotEmpty(validationCertificateQualifications)) {
				for (XmlValidationCertificateQualification validationCertificateQualification : validationCertificateQualifications) {
					if (validationTime == validationCertificateQualification.getValidationTime()) {
						return validationCertificateQualification.getCertificateQualification();
					}
				}
			}
		}
		return CertificateQualification.NA;
	}

	public XmlConclusion getCertificateXCVConclusion(String certificateId) {
		if (jaxbDetailedReport.getCertificate() == null) {
			throw new DSSException("Only supported in report for certificate");
		}
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
			XmlXCV xcv = xmlBasicBuildingBlocks.getXCV();
			if (xcv != null) {
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				for (XmlSubXCV xmlSubXCV : subXCV) {
					if (Utils.areStringsEqual(certificateId, xmlSubXCV.getId())) {
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

	public Indication getHighestIndication(String signatureId) {
		return getHighestConclusion(signatureId).getConclusion().getIndication();
	}

	public SubIndication getHighestSubIndication(String signatureId) {
		return getHighestConclusion(signatureId).getConclusion().getSubIndication();
	}

	private XmlConstraintsConclusion getHighestConclusion(String signatureId) {
		XmlSignature xmlSignature = getXmlSignatureById(signatureId);
		if (xmlSignature.getValidationProcessArchivalData() != null) {
			return xmlSignature.getValidationProcessArchivalData();
		} else if (xmlSignature.getValidationProcessLongTermData() != null) {
			return xmlSignature.getValidationProcessLongTermData();
		} else {
			return xmlSignature.getValidationProcessBasicSignatures();
		}
	}

	public Set<String> getErrors(String signatureId) {
		return collect(MessageType.ERROR, signatureId);
	}

	public Set<String> getWarnings(String signatureId) {
		return collect(MessageType.WARN, signatureId);
	}

	public Set<String> getInfos(String signatureId) {
		return collect(MessageType.INFO, signatureId);
	}

	public Set<String> collect(MessageType type, String signatureId) {
		Set<String> result = new LinkedHashSet<String>();

		XmlSignature signatureById = getXmlSignatureById(signatureId);

		XmlValidationSignatureQualification validationSignatureQualification = signatureById
				.getValidationSignatureQualification();
		if (validationSignatureQualification != null) {
			List<XmlValidationCertificateQualification> validationCertificateQualifications = validationSignatureQualification
					.getValidationCertificateQualification();
			for (XmlValidationCertificateQualification validationCertificateQualification : validationCertificateQualifications) {
				collect(type, result, validationCertificateQualification);
			}
			collect(type, result, validationSignatureQualification);
		}

		if (MessageType.ERROR == type) {
			collect(type, result, getHighestConclusion(signatureId));
			collectTimestamps(type, result, signatureById);
		} else {
			collect(type, result, signatureById.getValidationProcessBasicSignatures());
			collectTimestamps(type, result, signatureById);
			collect(type, result, signatureById.getValidationProcessLongTermData());
			collect(type, result, signatureById.getValidationProcessArchivalData());
		}

		return result;
	}

	private void collectTimestamps(MessageType type, Set<String> result, XmlSignature signatureById) {
		List<XmlValidationProcessTimestamps> validationProcessTimestamps = signatureById.getValidationProcessTimestamps();
		for (XmlValidationProcessTimestamps xmlValidationProcessTimestamp : validationProcessTimestamps) {
			collect(type, result, xmlValidationProcessTimestamp);
		}
	}

	private void collect(MessageType type, Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		if (constraintConclusion != null && Utils.isCollectionNotEmpty(constraintConclusion.getConstraint())) {
			for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
				XmlName message = getMessage(type, constraint);
				if (message != null) {
					result.add(message.getValue());
				}

				if (Utils.isStringNotBlank(constraint.getId())) {
					collect(type, result, getBasicBuildingBlockById(constraint.getId()));
				}
			}
		}
	}

	private void collect(MessageType type, Set<String> result, XmlBasicBuildingBlocks bbb) {
		if (bbb != null) {
			collect(type, result, bbb.getFC());
			collect(type, result, bbb.getISC());
			collect(type, result, bbb.getCV());
			collect(type, result, bbb.getSAV());
			XmlXCV xcv = bbb.getXCV();
			if (xcv != null) {
				collect(type, result, xcv);
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				if (Utils.isCollectionNotEmpty(subXCV)) {
					for (XmlSubXCV xmlSubXCV : subXCV) {
						collect(type, result, xmlSubXCV);
					}
				}
			}
			collect(type, result, bbb.getVCI());
		}
	}

	private XmlName getMessage(MessageType type, XmlConstraint constraint) {
		XmlName message = null;
		switch (type) {
		case ERROR:
			message = constraint.getError();
			break;
		case WARN:
			message = constraint.getWarning();
			break;
		case INFO:
			message = constraint.getInfo();
			break;
		default:
			break;
		}
		return message;
	}

	enum MessageType {
		INFO, WARN, ERROR
	}

}
