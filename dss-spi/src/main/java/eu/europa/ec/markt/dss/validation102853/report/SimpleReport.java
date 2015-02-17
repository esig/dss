/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import eu.europa.ec.markt.dss.validation102853.SignatureType;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * A SimpleReport holder to fetch properties from a XmlDom simpleReport.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class SimpleReport extends XmlDom {

	public SimpleReport(final Document document) {

		super(document);
	}

	/**
	 * This method returns the validation time.
	 *
	 * @return
	 */
	public Date getValidationTime() {

		final Date validationTime = getTimeValue("/SimpleReport/ValidationTime/text()");
		return validationTime;
	}

	/**
	 * This method returns the indication obtained after the validation of the signature.
	 *
	 * @param signatureId DSS unique identifier of the signature
	 * @return
	 */
	public String getIndication(final String signatureId) {

		final String indication = getValue("/SimpleReport/Signature[@Id='%s']/Indication/text()", signatureId);
		return indication;
	}

	/**
	 * This method returns the sub-indication obtained after the validation of the signature.
	 *
	 * @param signatureId DSS unique identifier of the signature
	 * @return
	 */
	public String getSubIndication(final String signatureId) {

		final String subIndication = getValue("/SimpleReport/Signature[@Id='%s']/SubIndication/text()", signatureId);
		return subIndication;
	}

	/**
	 * @param signatureId the signature id to test
	 * @return true if the signature Indication element is equals to {@link Indication#VALID}
	 */
	public boolean isSignatureValid(final String signatureId) {

		final String indicationValue = getIndication(signatureId);
		return Indication.VALID.equals(indicationValue);
	}

	/**
	 * Returns the signature type: QES, AdES, AdESqc, NA
	 *
	 * @param signatureId
	 * @return {@code SignatureType}
	 */
	public SignatureType getSignatureLevel(final String signatureId) {

		final String signatureTypeString = getValue("/SimpleReport/Signature[@Id='%s']/SignatureLevel/text()", signatureId);
		SignatureType signatureType;
		try {
			signatureType = SignatureType.valueOf(signatureTypeString);
		} catch (IllegalArgumentException e) {
			signatureType = SignatureType.NA;
		}
		return signatureType;
	}

	/**
	 * @return the list of signature id contained in the simpleReport
	 * @deprecated FROM 4.3.0-RC, use getSignatureIdList()
	 */
	@Deprecated
	public List<String> getSignatureIds() {

		final List<String> signatureIdList = new ArrayList<String>();
		final List<XmlDom> signatures = getElements("/SimpleReport/Signature");
		for (final XmlDom signature : signatures) {
			signatureIdList.add(signature.getAttribute("Id"));
		}
		return signatureIdList;
	}

	/**
	 * @return the {@code List} of signature id(s) contained in the simpleReport
	 */
	public List<String> getSignatureIdList() {

		final List<String> signatureIdList = new ArrayList<String>();
		final List<XmlDom> signatures = getElements("/SimpleReport/Signature");
		for (final XmlDom signature : signatures) {
			signatureIdList.add(signature.getAttribute("Id"));
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

	public List<Conclusion.BasicInfo> getInfo(final String signatureId) {

		final List<Conclusion.BasicInfo> infoList = getBasicInfo(signatureId, "Info");
		return infoList;
	}

	public List<Conclusion.BasicInfo> getErrors(final String signatureId) {

		final List<Conclusion.BasicInfo> errorList = getBasicInfo(signatureId, "Error");
		return errorList;
	}

	public List<Conclusion.BasicInfo> getWarnings(final String signatureId) {

		final List<Conclusion.BasicInfo> errorList = getBasicInfo(signatureId, "Warning");
		return errorList;
	}

	private List<Conclusion.BasicInfo> getBasicInfo(final String signatureId, final String basicInfoType) {

		final List<XmlDom> elementList = getElements("/SimpleReport/Signature[@Id='%s']/" + basicInfoType, signatureId);
		final List<Conclusion.BasicInfo> infoList = new ArrayList<Conclusion.BasicInfo>();
		for (final XmlDom infoElement : elementList) {

			Conclusion.BasicInfo basicInfo = new Conclusion.BasicInfo(basicInfoType);
			basicInfo.setValue(infoElement.getText());
			final NamedNodeMap attributes = infoElement.getAttributes();
			for (int index = 0; index < attributes.getLength(); index++) {

				final Node attribute = attributes.item(index);
				basicInfo.setAttribute(attribute.getNodeName(), attribute.getNodeValue());
			}
			infoList.add(basicInfo);
		}
		return infoList;
	}

	/**
	 * This method returns the signature format (XAdES_BASELINE_B...)
	 *
	 * @param signatureId
	 * @return
	 */
	public String getSignatureFormat(final String signatureId) {

		final String indication = getValue("/SimpleReport/Signature[@Id='%s']/@SignatureFormat", signatureId);
		return indication;
	}
}
