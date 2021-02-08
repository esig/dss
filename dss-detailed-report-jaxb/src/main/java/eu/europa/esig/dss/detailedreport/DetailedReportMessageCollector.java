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
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTLAnalysis;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.jaxb.object.Message;

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
	 * Returns a list of errors from the report for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation errors for
	 * @return a list of {@link Message}s
	 */
	List<Message> getValidationErrors(String tokenId) {
		return collect(MessageType.ERROR, tokenId);
	}

	/**
	 * Returns a list of warnings from the report for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation warnings for
	 * @return a list of {@link Message}s
	 */

	List<Message> getValidationWarnings(String tokenId) {
		return collect(MessageType.WARN, tokenId);
	}

	/**
	 * Returns a list of infos from the report for a token with the given id
	 * 
	 * @param tokenId {@link String} id of a token to get validation infos for
	 * @return a list of {@link Message}s
	 */
	List<Message> getValidationInfos(String tokenId) {
		return collect(MessageType.INFO, tokenId);
	}

	/**
	 * Returns a list of qualification validation errors for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification errors for
	 * @return a list of {@link Message}s
	 */

	List<Message> getQualificationErrors(String tokenId) {
		return collectQualification(MessageType.ERROR, tokenId);
	}

	/**
	 * Returns a list of qualification validation warnings for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification warnings for
	 * @return a list of {@link Message}s
	 */
	List<Message> getQualificationWarnings(String tokenId) {
		return collectQualification(MessageType.WARN, tokenId);
	}

	/**
	 * Returns a list of qualification validation infos for a token with the given id
	 *
	 * @param tokenId {@link String} id of a token to get qualification infos for
	 * @return a list of {@link Message}s
	 */
	List<Message> getQualificationInfos(String tokenId) {
		return collectQualification(MessageType.INFO, tokenId);
	}

	private List<Message> collect(MessageType type, String tokenId) {
		XmlSignature signatureById = detailedReport.getXmlSignatureById(tokenId);
		if (signatureById != null) {
			return collectSignatureValidation(type, signatureById);
		}
		XmlTimestamp timestampById = detailedReport.getXmlTimestampById(tokenId);
		if (timestampById != null) {
			return collectTimestampValidation(type, timestampById);
		}
		XmlTLAnalysis tlAnalysisById = detailedReport.getTLAnalysisById(tokenId);
		if (timestampById != null) {
			return getMessages(type, tlAnalysisById.getConclusion());
		}
		XmlBasicBuildingBlocks bbbById = detailedReport.getBasicBuildingBlockById(tokenId);
		if (bbbById != null) {
			return getMessages(type, bbbById.getConclusion());
		}
		return Collections.emptyList();
	}

	private List<Message> collectQualification(MessageType type, String tokenId) {
		XmlSignature signatureById = detailedReport.getXmlSignatureById(tokenId);
		if (signatureById != null) {
			return collectSignatureQualification(type, signatureById);
		}
		XmlTimestamp timestampById = detailedReport.getXmlTimestampById(tokenId);
		if (timestampById != null) {
			return collectTimestampQualification(type, timestampById);
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
		return getMessages(type, validationProcessTimestamps.getConclusion());
	}

	private List<Message> collectSignatureQualification(MessageType type, XmlSignature xmlSignature) {
		List<Message> result = new ArrayList<>();
		addMessages(result, getMessages(type, xmlSignature.getValidationSignatureQualification()));
		return result;
	}

	private List<Message> collectTimestampQualification(MessageType type, XmlTimestamp xmlTimestamp) {
		return getMessages(type, xmlTimestamp.getValidationTimestampQualification());
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
