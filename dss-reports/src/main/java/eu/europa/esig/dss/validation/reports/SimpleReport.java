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
import java.util.Collections;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignatureLevel;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureQualification;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;

/**
 * A SimpleReport holder to fetch properties from a XmlDom simpleReport.
 */
public class SimpleReport {

	private final eu.europa.esig.dss.jaxb.simplereport.SimpleReport simpleReport;

	public SimpleReport(final eu.europa.esig.dss.jaxb.simplereport.SimpleReport simpleReport) {
		this.simpleReport = simpleReport;
	}

	/**
	 * This method returns the validation time.
	 *
	 * @return
	 */
	public Date getValidationTime() {
		return simpleReport.getValidationTime();
	}

	/**
	 * This method returns the indication obtained after the validation of the signature.
	 *
	 * @param signatureId
	 *            DSS unique identifier of the signature
	 * @return
	 */
	public Indication getIndication(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getIndication();
		}
		return null;
	}

	/**
	 * This method returns the sub-indication obtained after the validation of the signature.
	 *
	 * @param signatureId
	 *            DSS unique identifier of the signature
	 * @return
	 */
	public SubIndication getSubIndication(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getSubIndication();
		}
		return null;
	}

	/**
	 * @param signatureId
	 *            the signature id to test
	 * @return true if the signature Indication element is equals to {@link Indication#TOTAL_PASSED}
	 */
	public boolean isSignatureValid(final String signatureId) {
		final Indication indicationValue = getIndication(signatureId);
		return Indication.TOTAL_PASSED.equals(indicationValue);
	}

	/**
	 * Returns the signature type: QES, AdES, AdESqc, NA
	 *
	 * @param signatureId
	 * @return {@code SignatureType}
	 */
	public SignatureQualification getSignatureQualification(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		XmlSignatureLevel signatureLevel = signature.getSignatureLevel();
		SignatureQualification qualif = SignatureQualification.NA;
		if (signatureLevel != null) {
			qualif = signatureLevel.getValue();
		}
		return qualif;
	}

	/**
	 * @return the {@code List} of signature id(s) contained in the simpleReport
	 */
	public List<String> getSignatureIdList() {
		final List<String> signatureIdList = new ArrayList<String>();
		List<XmlSignature> signatures = simpleReport.getSignature();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				signatureIdList.add(xmlSignature.getId());
			}
		}
		return signatureIdList;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return
	 */
	public String getFirstSignatureId() {
		final List<String> signatureIdList = getSignatureIdList();
		if (signatureIdList.size() > 0) {
			return signatureIdList.get(0);
		}
		return null;
	}

	public List<String> getInfo(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getInfos();
		}
		return Collections.emptyList();
	}

	public List<String> getErrors(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getErrors();
		}
		return Collections.emptyList();
	}

	public List<String> getWarnings(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getWarnings();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns the signature format (XAdES_BASELINE_B...)
	 *
	 * @param signatureId
	 * @return
	 */
	public String getSignatureFormat(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSignatureFormat();
		}
		return Utils.EMPTY_STRING;
	}

	/**
	 * This method returns the signature time
	 *
	 * @param signatureId
	 * @return
	 */
	public Date getSigningTime(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSigningTime();
		}
		return null;
	}

	/**
	 * This method returns the signedBy
	 *
	 * @param signatureId
	 * @return
	 */
	public String getSignedBy(final String signatureId) {
		XmlSignature xmlSignature = getSignatureById(signatureId);
		if (xmlSignature != null) {
			return xmlSignature.getSignedBy();
		}
		return Utils.EMPTY_STRING;
	}

	/**
	 * This method returns the number of signatures
	 * 
	 * @return
	 */
	public int getSignaturesCount() {
		return simpleReport.getSignaturesCount();
	}

	/**
	 * This method returns the number of valid signatures
	 * 
	 * @return
	 */
	public int getValidSignaturesCount() {
		return simpleReport.getValidSignaturesCount();
	}

	private XmlSignature getSignatureById(String signatureId) {
		List<XmlSignature> signatures = simpleReport.getSignature();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	public eu.europa.esig.dss.jaxb.simplereport.SimpleReport getJaxbModel() {
		return simpleReport;
	}

}
