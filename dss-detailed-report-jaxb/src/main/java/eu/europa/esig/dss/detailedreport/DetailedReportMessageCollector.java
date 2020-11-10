package eu.europa.esig.dss.detailedreport;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
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
	 * @return a set of {@link String}s
	 */
	Set<String> getErrors(String signatureId) {
		return collect(MessageType.ERROR, signatureId);
	}

	/**
	 * Returns a set of warnings from the report for a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to get validation warnings for
	 * @return a set of {@link String}s
	 */
	Set<String> getWarnings(String signatureId) {
		return collect(MessageType.WARN, signatureId);
	}

	/**
	 * Returns a set of infos from the report for a signature with the given id
	 * 
	 * @param signatureId {@link String} id of a signature to get validation infos for
	 * @return a set of {@link String}s
	 */
	Set<String> getInfos(String signatureId) {
		return collect(MessageType.INFO, signatureId);
	}

	private Set<String> collect(MessageType type, String signatureId) {
		Set<String> result = new LinkedHashSet<>();

		XmlSignature signatureById = detailedReport.getXmlSignatureById(signatureId);

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
			collect(type, result, detailedReport.getHighestConclusion(signatureId));
			collectTimestamps(type, result, signatureById);
		} else {
			collect(type, result, signatureById.getValidationProcessBasicSignature());
			collectTimestamps(type, result, signatureById);
			collect(type, result, signatureById.getValidationProcessLongTermData());
			collect(type, result, signatureById.getValidationProcessArchivalData());
		}

		return result;
	}

	private void collectTimestamps(MessageType type, Set<String> result, XmlSignature signatureById) {
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

	private void collect(MessageType type, Set<String> result, XmlConstraintsConclusion constraintConclusion) {
		collect(type, result, constraintConclusion, null);
	}

	private void collect(MessageType type, Set<String> result, XmlConstraintsConclusion constraintConclusion,
			String bbbId) {
		if (constraintConclusion != null && constraintConclusion.getConstraint() != null) {
			for (XmlConstraint constraint : constraintConclusion.getConstraint()) {
				XmlName message = getMessage(type, constraint);
				if (message != null) {
					result.add(message.getValue());
				}
				
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
				result.addAll(getMessages(type, constraintConclusion.getConclusion()));
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
				if (subXCV != null) {
					for (XmlSubXCV xmlSubXCV : subXCV) {
						collect(type, result, xmlSubXCV, bbb.getId());
					}
				}
			}
			collect(type, result, bbb.getVCI());
		}
	}
	
	private void collect(MessageType type, Set<String> result, XmlTLAnalysis xmlTLAnalysis) {
		if (xmlTLAnalysis != null) {
			collect(type, result, (XmlConstraintsConclusion) xmlTLAnalysis);
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
	
	private Set<String> getMessages(MessageType type, XmlConclusion conclusion) {
		switch (type) {
			case ERROR:
				return getMessages(conclusion.getErrors());
			case WARN:
				return getMessages(conclusion.getWarnings());
			case INFO:
				return getMessages(conclusion.getInfos());
			default:
				return Collections.emptySet();
		}
	}
	
	private Set<String> getMessages(List<XmlName> xmlNames) {
		Set<String> messages = new HashSet<>();
		if (xmlNames != null) {
			for (XmlName xmlName : xmlNames) {
				messages.add(xmlName.getValue());
			}
		}
		return messages;
	}

	private enum MessageType {
		INFO, WARN, ERROR
	}

}
