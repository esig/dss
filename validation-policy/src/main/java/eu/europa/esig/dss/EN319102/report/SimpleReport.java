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
package eu.europa.esig.dss.EN319102.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.EN319102.policy.SignatureType;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
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
	 * @return true if the signature Indication element is equals to {@link Indication#VALID}
	 */
	public boolean isSignatureValid(final String signatureId) {
		final Indication indicationValue = getIndication(signatureId);
		return Indication.VALID.equals(indicationValue);
	}

	/**
	 * Returns the signature type: QES, AdES, AdESqc, NA
	 *
	 * @param signatureId
	 * @return {@code SignatureType}
	 */
	public SignatureType getSignatureLevel(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		SignatureType signatureType = SignatureType.NA;
		if (signature != null) {
			try {
				signatureType = SignatureType.valueOf(signature.getSignatureLevel());
			} catch (IllegalArgumentException e) {
				signatureType = SignatureType.NA;
			}
		}
		return signatureType;
	}

	/**
	 * @return the {@code List} of signature id(s) contained in the simpleReport
	 */
	public List<String> getSignatureIdList() {
		final List<String> signatureIdList = new ArrayList<String>();
		List<XmlSignature> signatures = simpleReport.getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
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
		return StringUtils.EMPTY;
	}

	private XmlSignature getSignatureById(String signatureId) {
		List<XmlSignature> signatures = simpleReport.getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (StringUtils.equals(signatureId, xmlSignature.getId())) {
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
