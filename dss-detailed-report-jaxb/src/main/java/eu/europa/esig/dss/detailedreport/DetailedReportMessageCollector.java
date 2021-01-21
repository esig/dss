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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationTimestampQualification;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.jaxb.Message;

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
	 * Returns a set of errors from the report for a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to get validation errors for
	 * @return a list of {@link Message}s
	 */
	List<Message> getErrors(String signatureId) {
		return collect(MessageType.ERROR, signatureId);
	}

	/**
	 * Returns a set of warnings from the report for a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to get validation warnings for
	 * @return a list of {@link Message}s
	 */
	List<Message> getWarnings(String signatureId) {
		return collect(MessageType.WARN, signatureId);
	}

	/**
	 * Returns a set of infos from the report for a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to get validation infos for
	 * @return a list of {@link Message}s
	 */
	List<Message> getInfos(String signatureId) {
		return collect(MessageType.INFO, signatureId);
	}

	private List<Message> collect(MessageType type, String tokenId) {
		List<Message> result = new ArrayList<>();

		XmlSignature signatureById = detailedReport.getXmlSignatureById(tokenId);
		if (signatureById != null) {
			collect(type, result, signatureById);
			return result;
		}
		XmlTimestamp timestampById = detailedReport.getXmlTimestampById(tokenId);
		if (timestampById != null) {
			collect(type, result, timestampById);
			return result;
		}
		XmlTLAnalysis tlAnalysisById = detailedReport.getTLAnalysisById(tokenId);
		if (timestampById != null) {
			collect(type, result, tlAnalysisById);
			return result;
		}
		XmlBasicBuildingBlocks bbbById = detailedReport.getBasicBuildingBlockById(tokenId);
		if (bbbById != null) {
			collect(type, result, bbbById);
			return result;
		}

		return result;
	}

	private void collect(MessageType type, List<Message> result, XmlSignature signatureById) {
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
			collect(type, result, detailedReport.getHighestConclusion(signatureById.getId()));
			collectTimestamps(type, result, signatureById);
		} else {
			collect(type, result, signatureById.getValidationProcessBasicSignature());
			collectTimestamps(type, result, signatureById);
			collect(type, result, signatureById.getValidationProcessLongTermData());
			collect(type, result, signatureById.getValidationProcessArchivalData());
		}
	}

	private void collectTimestamps(MessageType type, List<Message> result, XmlSignature signatureById) {
		List<XmlTimestamp> timestamps = signatureById.getTimestamp();
		for (XmlTimestamp xmlTimestamp : timestamps) {
			XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
			if (validationTimestampQualification != null) {
				collect(type, result, validationTimestampQualification);
			}
			XmlValidationProcessTimestamp validationProcessTimestamps = xmlTimestamp.getValidationProcessTimestamp();
			if (!MessageType.ERROR.equals(type) || !Indication.PASSED.equals(
					detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId()).getConclusion().getIndication())) {
				collect(type, result, validationProcessTimestamps);
			}
		}
	}

	private void collect(MessageType type, List<Message> result, XmlTimestamp xmlTimestamp) {
		XmlValidationTimestampQualification validationTimestampQualification = xmlTimestamp.getValidationTimestampQualification();
		if (validationTimestampQualification != null) {
			collect(type, result, validationTimestampQualification);
		}
		XmlValidationProcessTimestamp validationProcessTimestamps = xmlTimestamp.getValidationProcessTimestamp();
		if (!MessageType.ERROR.equals(type) || !Indication.PASSED.equals(
				detailedReport.getBasicBuildingBlockById(xmlTimestamp.getId()).getConclusion().getIndication())) {
			collect(type, result, validationProcessTimestamps);
		}
	}

	private void collect(MessageType type, List<Message> result, XmlConstraintsConclusion constraintConclusion) {
		collect(type, result, constraintConclusion, null);
	}

	private void collect(MessageType type, List<Message> result, XmlConstraintsConclusion constraintConclusion,
			String bbbId) {
		if (constraintConclusion != null && constraintConclusion.getConstraint() != null) {
			for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
				Message message = getMessage(type, constraint);
				addMessage(result, message);
				
				// do not extract subErrors if the highest conclusion is valid
				if (!MessageType.ERROR.equals(type) || message != null) {
					String constraintId = constraint.getId();
					if (constraintId != null && !constraintId.isEmpty() && !constraintId.equals(bbbId)) {
						collect(type, result, detailedReport.getBasicBuildingBlockById(constraintId));
						collect(type, result, detailedReport.getTLAnalysisById(constraintId));
					}
				}

			}
			if (constraintConclusion.getConclusion() != null) {
				addMessages(result, getMessages(type, constraintConclusion.getConclusion()));
			}
		}
	}

	private void collect(MessageType type, List<Message> result, XmlBasicBuildingBlocks bbb) {
		if (bbb != null) {
			collect(type, result, bbb.getFC());
			collect(type, result, bbb.getISC());
			collect(type, result, bbb.getCV());
			collect(type, result, bbb.getSAV());
			XmlXCV xcv = bbb.getXCV();
			if (xcv != null) {
				collect(type, result, xcv);
				List<XmlSubXCV> subXCV = xcv.getSubXCV();
				if (subXCV != null) {
					for (XmlSubXCV xmlSubXCV : subXCV) {
						collect(type, result, xmlSubXCV, bbb.getId());
					}
				}
			}
			collect(type, result, bbb.getVCI());
		}
	}
	
	private void collect(MessageType type, List<Message> result, XmlTLAnalysis xmlTLAnalysis) {
		if (xmlTLAnalysis != null) {
			collect(type, result, (XmlConstraintsConclusion) xmlTLAnalysis);
		}
	}

	private Message getMessage(MessageType type, XmlConstraint constraint) {
		switch (type) {
			case ERROR:
				return convert(constraint.getError());
			case WARN:
				return convert(constraint.getWarning());
			case INFO:
				return convert(constraint.getInfo());
			default:
				return null;
		}
	}
	
	private List<Message> getMessages(MessageType type, XmlConclusion conclusion) {
		switch (type) {
			case ERROR:
				return convert(conclusion.getErrors());
			case WARN:
				return convert(conclusion.getWarnings());
			case INFO:
				return convert(conclusion.getInfos());
			default:
				return Collections.emptyList();
		}
	}

	private Message convert(XmlMessage m) {
		if (m != null) {
			return new Message(m.getKey(), m.getValue());
		}
		return null;
	}

	private List<Message> convert(Collection<XmlMessage> messages) {
		if (messages != null) {
			return messages.stream().map(m -> convert(m)).collect(Collectors.toList());
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

	private enum MessageType {
		INFO, WARN, ERROR
	}

}
