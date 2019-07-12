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

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.simplereport.XmlSignature;
import eu.europa.esig.dss.jaxb.simplereport.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;

/**
 * A SimpleReport holder to fetch values from a JAXB SimpleReport.
 */
public class SimpleReport {

	private final XmlSimpleReport wrapped;

	public SimpleReport(final XmlSimpleReport wrapped) {
		this.wrapped = wrapped;
	}

	/**
	 * This method returns the validation time.
	 *
	 * @return the validation time
	 */
	public Date getValidationTime() {
		return wrapped.getValidationTime();
	}

	/**
	 * This method returns the indication obtained after the validation of the signature.
	 *
	 * @param signatureId
	 *            DSS unique identifier of the signature
	 * @return the indication for the given signature Id
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
	 * @return the sub-indication for the given signature Id
	 */
	public SubIndication getSubIndication(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getSubIndication();
		}
		return null;
	}

	/**
	 * This method checks if the signature is valid (TOTAL_PASSED)
	 * 
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
	 *            the signature id to test
	 * @return the {@code SignatureQualification} of the given signature
	 */
	public SignatureQualification getSignatureQualification(final String signatureId) {
		SignatureQualification qualif = SignatureQualification.NA;
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null && signature.getSignatureLevel() != null) {
			qualif = signature.getSignatureLevel().getValue();
		}
		return qualif;
	}

	/**
	 * This method retrieves the signature ids
	 * 
	 * @return the {@code List} of signature id(s) contained in the simpleReport
	 */
	public List<String> getSignatureIdList() {
		final List<String> signatureIdList = new ArrayList<String>();
		List<XmlSignature> signatures = wrapped.getSignature();
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
	 * @return the first signature id
	 */
	public String getFirstSignatureId() {
		final List<String> signatureIdList = getSignatureIdList();
		if (signatureIdList.size() > 0) {
			return signatureIdList.get(0);
		}
		return null;
	}

	/**
	 * This method retrieve the information for a given signature id
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the linked information
	 */
	public List<String> getInfo(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getInfos();
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the errors for a given signature id
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the linked errors
	 */
	public List<String> getErrors(final String signatureId) {
		XmlSignature signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getErrors();
		}
		return Collections.emptyList();
	}

	/**
	 * This method retrieve the warnings for a given signature id
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the linked warnings
	 */
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
	 *            the signature id
	 * @return the linked signature format
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
	 *            the signature id
	 * @return the signing time
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
	 *            the signature id
	 * @return the signatory
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
	 * @return the number of signatures
	 */
	public int getSignaturesCount() {
		return wrapped.getSignaturesCount();
	}

	/**
	 * This method returns the number of valid signatures
	 * 
	 * @return the number of valid signatures
	 */
	public int getValidSignaturesCount() {
		return wrapped.getValidSignaturesCount();
	}

	/**
	 * This method returns a wrapper for the given signature
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the wrapper for the given signature id
	 */
	private XmlSignature getSignatureById(String signatureId) {
		List<XmlSignature> signatures = wrapped.getSignature();
		if (Utils.isCollectionNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (Utils.areStringsEqual(signatureId, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	/**
	 * This methods returns the jaxb model of the simple report
	 * 
	 * @return the jaxb model
	 */
	public XmlSimpleReport getJaxbModel() {
		return wrapped;
	}

}
