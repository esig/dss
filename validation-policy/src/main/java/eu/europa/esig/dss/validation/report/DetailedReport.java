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
package eu.europa.esig.dss.validation.report;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSignature;
import eu.europa.esig.dss.jaxb.detailedreport.XmlValidationProcessTimestamps;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * This class represents the detailed report built during the validation process. It contains information on each
 * executed constraint. It is composed among other of the
 * following building blocks:<br/>
 * - Identification of the Signer's Certificate (ISC)<br/>
 * - Validation Context Initialization (VCI)<br/>
 * - X.509 Certificate Validation (XCV)<br/>
 * - Cryptographic Verification (CV)<br/>
 * - Signature Acceptance Validation (SAV)<br/>
 * - Basic Validation Process<br/>
 * - Validation Process for Time-Stamps<br/>
 * - Validation Process for AdES-T<br/>
 * - Validation of LTV forms<br/>
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
	 * @return the Indication
	 */
	public Indication getBasicBuildingBlocksIndication(String tokenId) {
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
			if (StringUtils.equals(xmlBasicBuildingBlocks.getId(), tokenId)) {
				return xmlBasicBuildingBlocks.getConclusion().getIndication();
			}
		}
		return null;
	}

	/**
	 * This method returns the result of the Basic Building Block for a token (signature, timestamp, revocation)
	 * 
	 * @param tokenId
	 * @return the SubIndication
	 */
	public SubIndication getBasicBuildingBlocksSubIndication(String tokenId) {
		List<XmlBasicBuildingBlocks> basicBuildingBlocks = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks xmlBasicBuildingBlocks : basicBuildingBlocks) {
			if (StringUtils.equals(xmlBasicBuildingBlocks.getId(), tokenId)) {
				return xmlBasicBuildingBlocks.getConclusion().getSubIndication();
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
		if (CollectionUtils.size(bbbs) >= index) {
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
			if (StringUtils.equals(Context.SIGNATURE.name(), bbb.getType()) || StringUtils.equals(Context.COUNTER_SIGNATURE.name(), bbb.getType())) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	public List<String> getTimestampIds() {
		List<String> result = new ArrayList<String>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (StringUtils.equals(Context.TIMESTAMP.name(), bbb.getType())) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	public List<String> getRevocationIds() {
		List<String> result = new ArrayList<String>();
		List<XmlBasicBuildingBlocks> bbbs = jaxbDetailedReport.getBasicBuildingBlocks();
		for (XmlBasicBuildingBlocks bbb : bbbs) {
			if (StringUtils.equals(Context.REVOCATION.name(), bbb.getType())) {
				result.add(bbb.getId());
			}
		}
		return result;
	}

	public Indication getBasicValidationIndication(String signatureId) {
		XmlSignature signature = getXmlSignatureById(signatureId);
		if (signature != null && signature.getValidationProcessBasicSignatures() != null
				&& signature.getValidationProcessBasicSignatures().getConclusion() != null) {
			return signature.getValidationProcessBasicSignatures().getConclusion().getIndication();
		}
		return null;
	}

	public Indication getTimestampValidationIndication(String timestampId) {
		List<XmlSignature> signatures = jaxbDetailedReport.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				List<XmlValidationProcessTimestamps> validationTimestamps = xmlSignature.getValidationProcessTimestamps();
				if (CollectionUtils.isNotEmpty(validationTimestamps)) {
					for (XmlValidationProcessTimestamps tspValidation : validationTimestamps) {
						if (StringUtils.equals(tspValidation.getId(), timestampId) && tspValidation.getConclusion() != null) {
							return tspValidation.getConclusion().getIndication();
						}
					}
				}
			}
		}
		return null;
	}

	private XmlSignature getXmlSignatureById(String signatureId) {
		List<XmlSignature> signatures = jaxbDetailedReport.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (StringUtils.equals(signatureId, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	//
	// /**
	// * This method returns the {@code List} of the signature id based on the XML element:
	// * '/ValidationData/BasicBuildingBlocks/Signature' within the report.
	// *
	// * @return {@code List} of the signature id
	// */
	// public List<String> getBasicBuildingBlocksSignatureId() {
	//
	//// return getIdList("/ValidationData/BasicBuildingBlocks/Signature");
	// }
	//
	// /**
	// * This method returns the {@code List} of the signature id based on the XML element:
	// * '/ValidationData/TimestampValidationData/Signature' within the report.
	// *
	// * @return {@code List} of the signature id
	// */
	// public List<String> getTimestampValidationSignatureId() {
	//
	// return getIdList("/ValidationData/TimestampValidationData/Signature");
	// }
	//
	// /**
	// * This method returns the {@code List} of the timestamp id for the given {@code TimestampType} based on
	// * TimestampValidationData.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @param timestampType
	// * {@code TimestampType}
	// * @return {@code List} of timestamp id
	// */
	// public List<String> getTimestampValidationTimestampId(final String signatureId, final TimestampType
	// timestampType) {
	//
	// return getIdList("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Type='%s']",
	// signatureId, timestampType.name());
	// }
	//
	// /**
	// * Returns the validation INDICATION of the timestamp validation for the given signature id.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return related {@code Indication} indication
	// */
	// public Indication getTimestampValidationIndication(final String signatureId, final String timestampId) {
	// return Indication.valueOf(
	// getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/Indication/text()",
	// signatureId, timestampId));
	// }
	//
	// /**
	// * Returns the validation SUB_INDICATION of the timestamp validation for the given signature id.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return related {@code SubIndication} sub-indication
	// */
	// public SubIndication getTimestampValidationSubIndication(final String signatureId, final String timestampId) {
	// return SubIndication.forName(
	// getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/SubIndication/text()",
	// signatureId, timestampId));
	// }
	//
	// /**
	// * This method returns the {@code List} of the signature id based on the XML element:
	// * '/ValidationData/LongTermValidationData/Signature' within the report.
	// *
	// * @return {@code List} of the signature id
	// */
	// public List<String> getLongTermValidationSignatureId() {
	//
	// return getIdList("/ValidationData/LongTermValidationData/Signature");
	// }
	//
	// /**
	// * Returns the validation INDICATION of the long term validation for the given signature id.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return related {@code Indication} indication
	// */
	// public Indication getLongTermValidationIndication(final String signatureId) {
	// return
	// Indication.valueOf(getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/Indication/text()",
	// signatureId));
	// }
	//
	// /**
	// * Returns the validation SUB_INDICATION of the long term validation for the given signature id.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return related {@code SubIndication} sub-indication
	// */
	// public SubIndication getLongTermValidationSubIndication(final String signatureId) {
	// return
	// SubIndication.forName(getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()",
	// signatureId));
	// }
	//
	// /**
	// * This method checks if the basic building blocks have VALID indication. The check is performed for all
	// signatures.
	// *
	// * @return {@code true} if basic building blocks (for all signatures) have VALID indication, otherwise {@code
	// false}
	// */
	// public boolean areBasicBuildingBlocksValid() {
	//
	// final List<XmlDom> indications =
	// getElements("/ValidationData/BasicBuildingBlocks/Signature/Conclusion/Indication");
	// return areAllIndicationsValid(indications);
	// }
	//
	// /**
	// * This method returns the indication related to the AdESTValidation of a given signature.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return found {@code Indication} indication
	// */
	// public Indication getAdESTValidationIndication(final String signatureId) {
	// return
	// Indication.valueOf(getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/Indication/text()",
	// signatureId));
	// }
	//
	// /**
	// * This method returns the subIndication related to the AdESTValidation of a given signature.
	// *
	// * @param signatureId
	// * {@code String} id of the signature
	// * @return found {@code String} sub-indication
	// */
	// public SubIndication getAdESTValidationSubIndication(final String signatureId) {
	// return
	// SubIndication.forName(getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()",
	// signatureId));
	// }
	//
	// /**
	// * This method checks if the long term validation has VALID indication. The check is performed for all signatures.
	// *
	// * @return {@code true} if long term validation (for all signatures) has VALID indication, otherwise {@code false}
	// */
	// public boolean isLongTermValidationValid() {
	//
	// final List<XmlDom> indications =
	// getElements("/ValidationData/LongTermValidationData/Signature/Conclusion/Indication");
	// return areAllIndicationsValid(indications);
	// }
	//
	// /**
	// * This method checks if the timestamp validation has VALID indication. The check is performed for all signatures.
	// *
	// * @return {@code true} if timestamp validation (for all signatures) has VALID indication, otherwise {@code false}
	// */
	// public boolean isTimestampValidationValid() {
	//
	// final List<XmlDom> indications =
	// getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
	// return areAllIndicationsValid(indications);
	// }
	//
	// /**
	// * This method checks the timestamp validation indication for all signatures is VALID.
	// *
	// * @return {@code true} if VALID indication for all signatures, {@code null} if there is no timestamp, {@code
	// false}
	// * otherwise.
	// */
	// public Boolean isTimestampValidationValidOrEmpty() {
	//
	// final List<XmlDom> indications =
	// getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
	// if (indications.size() == 0) {
	// return null;
	// }
	// return areAllIndicationsValid(indications);
	// }
	//
	// /**
	// * This method returns the notice related to the signature policy.
	// *
	// * @param signatureId
	// * {@code String} id of the signature for which the check is to be done
	// * @return {@code String} describing the policy notice
	// */
	// public String getPolicyNotice(final String signatureId) {
	//
	// final String notice =
	// getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/VCI/Constraint/Notice/text()", signatureId);
	// return notice;
	// }
	//
	// /**
	// * This method returns the status of the constraint with the given tag.
	// *
	// * @param tag
	// * the tag of the constraint to find.
	// * @return the status of the constraint
	// */
	// public String getConstraintStatus(final MessageTag tag) {
	//
	// final String status = getValue("//Name[@NameId='%s']/../Status/text()", tag.name());
	// return status;
	// }
	//
	// /**
	// * This method returns the {@code List} of {@code String} id based on the given XPath query and set of optional
	// * parameters.
	// *
	// * @param xPath
	// * XPath query
	// * @param parameters
	// * array of {@code String }parameters
	// * @return {@code List} of id
	// */
	// private List<String> getIdList(final String xPath, final String... parameters) {
	//
	// final List<String> idList = new ArrayList<String>();
	//
	// final List<XmlDom> elements = getElements(xPath, parameters);
	// for (final XmlDom element : elements) {
	//
	// final String id = element.getAttribute("Id");
	// idList.add(id);
	// }
	//
	// return idList;
	// }
	//
	// /**
	// * This method checks if all indications contained within the {@code indications} are VALID.
	// *
	// * @param indications
	// * {@code List} of {@code XmlDom} containing the INDICATION
	// * @return {@code true} if all contained indications are equal to VALID, otherwise {@code false}
	// */
	// private boolean areAllIndicationsValid(final List<XmlDom> indications) {
	//
	// boolean valid = indications.size() > 0;
	// for (final XmlDom indicationDom : indications) {
	//
	// final String indication = indicationDom.getText();
	// valid = valid && Indication.VALID.name().equals(indication);
	// }
	// return valid;
	// }

}
