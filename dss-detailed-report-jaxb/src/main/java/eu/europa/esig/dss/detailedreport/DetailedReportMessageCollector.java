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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MessageType;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.jaxb.object.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The class is used to collect all messages for a token validation by a defined type from a DetailedReport
 *
 */
public class DetailedReportMessageCollector {

	private static final Logger LOG = LoggerFactory.getLogger(DetailedReportMessageCollector.class);
	
	/** The DetailedReport used to collect messages from */
	private final DetailedReport detailedReport;
	
	/**
	 * The default constructor
	 * 
	 * @param detailedReport {@link DetailedReport} to collect messages from
	 */
	DetailedReportMessageCollector(final DetailedReport detailedReport) {
		Objects.requireNonNull(detailedReport, "DetailedReport cannot be null!");
		this.detailedReport = detailedReport;
	}
	
	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation error messages for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation errors for
	 * @return a list of {@link Message}s
	 */
	List<Message> getAdESValidationErrors(String tokenId) {
		return collectAdESValidationMessages(MessageType.ERROR, tokenId);
	}

	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation warning messages for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation warnings for
	 * @return a list of {@link Message}s
	 */

	List<Message> getAdESValidationWarnings(String tokenId) {
		return collectAdESValidationMessages(MessageType.WARN, tokenId);
	}

	/**
	 * Returns a list of ETSI EN 319 102-1 AdES validation info messages for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation infos for
	 * @return a list of {@link Message}s
	 */
	List<Message> getAdESValidationInfos(String tokenId) {
		return collectAdESValidationMessages(MessageType.INFO, tokenId);
	}

	/**
	 * Returns a list of qualification validation errors for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification errors for
	 * @return a list of {@link Message}s
	 */

	List<Message> getQualificationErrors(String tokenId) {
		return collectQualificationMessages(MessageType.ERROR, tokenId);
	}

	/**
	 * Returns a list of qualification validation warnings for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	List<Message> getQualificationWarnings(String tokenId) {
		return collectQualificationMessages(MessageType.WARN, tokenId);
	}

	/**
	 * Returns a list of qualification validation infos for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification infos for
	 * @return a list of {@link Message}s
	 */
	List<Message> getQualificationInfos(String tokenId) {
		return collectQualificationMessages(MessageType.INFO, tokenId);
	}

	/**
	 * Returns a list of qualification validation errors for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification errors for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationErrorsAtIssuanceTime(String certificateId) {
		return collectCertificateQualificationAtIssuanceTime(MessageType.ERROR, certificateId);
	}

	/**
	 * Returns a list of qualification validation warnings for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationWarningsAtIssuanceTime(String certificateId) {
		return collectCertificateQualificationAtIssuanceTime(MessageType.WARN, certificateId);
	}

	/**
	 * Returns a list of qualification validation information messages for a certificate with the given id at certificate issuance time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification information messages for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationInfosAtIssuanceTime(String certificateId) {
		return collectCertificateQualificationAtIssuanceTime(MessageType.INFO, certificateId);
	}

	/**
	 * Returns a list of qualification validation errors for a certificate with the given id at validation time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification errors for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationErrorsAtValidationTime(String certificateId) {
		return collectCertificateQualificationAtValidationTime(MessageType.ERROR, certificateId);
	}

	/**
	 * Returns a list of qualification validation warnings for a certificate with the given id at validation time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationWarningsAtValidationTime(String certificateId) {
		return collectCertificateQualificationAtValidationTime(MessageType.WARN, certificateId);
	}

	/**
	 * Returns a list of qualification validation information messages for a certificate with the given id at validation time
	 * NOTE: applicable only for certificate validation
	 *
	 * @param certificateId {@link String} id of a certificate to get qualification information messages for
	 * @return a list of {@link Message}s
	 */
	List<Message> getCertificateQualificationInfosAtValidationTime(String certificateId) {
		return collectCertificateQualificationAtValidationTime(MessageType.INFO, certificateId);
	}

	private List<Message> collectAdESValidationMessages(MessageType type, String tokenId) {
		XmlSignature signatureById = detailedReport.getXmlSignatureById(tokenId);
		if (signatureById != null) {
			return collectSignatureValidation(type, signatureById);
		}
		XmlTimestamp timestampById = detailedReport.getXmlTimestampById(tokenId);
		if (timestampById != null) {
			return collectTimestampValidation(type, timestampById);
		}
		XmlTLAnalysis tlAnalysisById = detailedReport.getTLAnalysisById(tokenId);
		if (tlAnalysisById != null) {
			return getMessages(type, tlAnalysisById.getConclusion());
		}
		XmlBasicBuildingBlocks bbbById = detailedReport.getBasicBuildingBlockById(tokenId);
		if (bbbById != null) {
			return getMessages(type, bbbById.getConclusion());
		}
		// supported only for certificate validation
		if (detailedReport.isCertificateValidation()) {
			XmlConclusion certXCVConclusion = detailedReport.getCertificateXCVConclusion(tokenId);
			if (certXCVConclusion != null) {
				return getMessages(type, certXCVConclusion);
			}
		}
		return Collections.emptyList();
	}

	private List<Message> collectQualificationMessages(MessageType type, String tokenId) {
		XmlSignature signatureById = detailedReport.getXmlSignatureById(tokenId);
		if (signatureById != null) {
			return collectSignatureQualification(type, signatureById);
		}
		XmlTimestamp timestampById = detailedReport.getXmlTimestampById(tokenId);
		if (timestampById != null) {
			return collectTimestampQualification(type, timestampById);
		}
		XmlCertificate certificateById = detailedReport.getXmlCertificateById(tokenId);
		if (certificateById != null) {
			return collectCertificateQualification(type, certificateById);
		}
		return Collections.emptyList();
	}

	private List<Message> collectSignatureValidation(MessageType type, XmlSignature xmlSignature) {
		List<Message> result = new ArrayList<>();

		XmlConstraintsConclusion highestConclusion = detailedReport.getHighestConclusion(xmlSignature.getId());
		if (MessageType.ERROR != type || !Indication.PASSED.equals(highestConclusion.getConclusion().getIndication())) {
			addMessages(result, getMessages(type, xmlSignature.getValidationProcessBasicSignature()));
			addMessages(result, getMessages(type, xmlSignature.getValidationProcessLongTermData()));
		}
		addMessages(result, getMessages(type, highestConclusion));
		return result;
	}

	private List<Message> collectTimestampValidation(MessageType type, XmlTimestamp xmlTimestamp) {
		XmlValidationProcessTimestamp validationProcessTimestamps = xmlTimestamp.getValidationProcessTimestamp();

		XmlConclusion conclusion = new XmlConclusion();
		conclusion.getWarnings().addAll(validationProcessTimestamps.getConclusion().getWarnings());
		conclusion.getInfos().addAll(validationProcessTimestamps.getConclusion().getInfos());

		XmlBasicBuildingBlocks tstBBB = detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId());
		XmlPSV psv = tstBBB.getPSV();
		if (psv == null || psv.getConclusion() == null || !Indication.PASSED.equals(psv.getConclusion().getIndication())) {
			conclusion.getErrors().addAll(validationProcessTimestamps.getConclusion().getErrors());
		}
		return getMessages(type, conclusion);
	}

	private List<Message> collectSignatureQualification(MessageType type, XmlSignature xmlSignature) {
		List<Message> result = new ArrayList<>();
		addMessages(result, getMessages(type, xmlSignature.getValidationSignatureQualification()));
		return result;
	}

	private List<Message> collectTimestampQualification(MessageType type, XmlTimestamp xmlTimestamp) {
		return getMessages(type, xmlTimestamp.getValidationTimestampQualification());
	}

	private List<Message> collectCertificateQualification(MessageType type, XmlCertificate xmlCertificate) {
		List<Message> result = new ArrayList<>();
		result.addAll(collectCertificateQualificationAtIssuanceTime(type, xmlCertificate));
		result.addAll(collectCertificateQualificationAtBestSignatureTime(type, xmlCertificate));
		result.addAll(collectCertificateQualificationAtValidationTime(type, xmlCertificate));
		return result;
	}

	private List<Message> collectCertificateQualificationAtIssuanceTime(MessageType type, XmlCertificate xmlCertificate) {
		return collectCertificateQualificationAtTime(type, xmlCertificate, ValidationTime.CERTIFICATE_ISSUANCE_TIME);
	}

	private List<Message> collectCertificateQualificationAtBestSignatureTime(MessageType type, XmlCertificate xmlCertificate) {
		return collectCertificateQualificationAtTime(type, xmlCertificate, ValidationTime.BEST_SIGNATURE_TIME);
	}

	private List<Message> collectCertificateQualificationAtValidationTime(MessageType type, XmlCertificate xmlCertificate) {
		return collectCertificateQualificationAtTime(type, xmlCertificate, ValidationTime.VALIDATION_TIME);
	}

	private List<Message> collectCertificateQualificationAtIssuanceTime(MessageType type, String certificateId) {
		XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
		if (xmlCertificate != null) {
			return collectCertificateQualificationAtIssuanceTime(type, xmlCertificate);
		}
		return Collections.emptyList();
	}

	private List<Message> collectCertificateQualificationAtValidationTime(MessageType type, String certificateId) {
		XmlCertificate xmlCertificate = detailedReport.getXmlCertificateById(certificateId);
		if (xmlCertificate != null) {
			return collectCertificateQualificationAtValidationTime(type, xmlCertificate);
		}
		return Collections.emptyList();
	}

	private List<Message> collectCertificateQualificationAtTime(MessageType type, XmlCertificate xmlCertificate, ValidationTime validationTime) {
		for (XmlValidationCertificateQualification certificateQualification : xmlCertificate.getValidationCertificateQualification()) {
			if (validationTime.equals(certificateQualification.getValidationTime())) {
				return getMessages(type,certificateQualification);
			}
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("The validation at time '{}' is not found or not performed!", validationTime);
		}
		return Collections.emptyList();
	}

	private List<Message> getMessages(MessageType type, XmlConstraintsConclusion constraintsConclusion) {
		if (constraintsConclusion != null) {
			return getMessages(type, constraintsConclusion.getConclusion());
		}
		return Collections.emptyList();
	}
	
	private List<Message> getMessages(MessageType type, XmlConclusion conclusion) {
		if (conclusion != null) {
			switch (type) {
				case ERROR:
					return convert(conclusion.getErrors());
				case WARN:
					return convert(conclusion.getWarnings());
				case INFO:
					return convert(conclusion.getInfos());
				default:
					break;
			}
		}
		return Collections.emptyList();
	}

	private Message convert(XmlMessage m) {
		if (m != null) {
			return new Message(m.getKey(), m.getValue());
		}
		return null;
	}

	private List<Message> convert(Collection<XmlMessage> messages) {
		if (messages != null) {
			return messages.stream().map(this::convert).collect(Collectors.toList());
		}
		return Collections.emptyList();
	}

	private void addMessage(List<Message> result, Message toAdd) {
		if (toAdd != null && !result.contains(toAdd)) {
			result.add(toAdd);
		}
	}

	private void addMessages(List<Message> result, Collection<Message> toAdd) {
		if (toAdd != null) {
			for (Message m : toAdd) {
				addMessage(result, m);
			}
		}
	}

}
