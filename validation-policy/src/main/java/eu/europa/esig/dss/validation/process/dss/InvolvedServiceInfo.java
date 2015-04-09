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
package eu.europa.esig.dss.validation.process.dss;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.XmlDom;

/**
 * This class allows to retrieve the appropriated TSP service (current or historical) for the given certificate and the given date time.
 *
 */
public class InvolvedServiceInfo {

	/**
	 * This method returns the TSPName.
	 *
	 * @param trustedAnchor The trust anchor belonging to the service.
	 * @return
	 */
	public static String getTSPName(final XmlDom trustedAnchor) {

		final String tspName = trustedAnchor.getValue("./TrustedServiceProvider/TSPName/text()");
		return tspName;
	}

	/**
	 * This method returns the ServiceTypeIdentifier related to the certificate .
	 *
	 * @param cert The certificate.
	 * @return
	 */
	public static String getServiceTypeIdentifier(final XmlDom cert) {

		final String serviceTypeIdentifier = cert.getValue("./TrustedServiceProvider/TSPServiceType/text()");
		return serviceTypeIdentifier;
	}

	/**
	 * This method returns the ServiceName related to the certificate.
	 *
	 * @param cert The certificate
	 * @return
	 */
	public static String getServiceName(final XmlDom cert) {

		final String serviceName = cert.getValue("./TrustedServiceProvider/TSPServiceName/text()");
		return serviceName;
	}

	/**
	 * This method returns the status of the associated TSP service.
	 *
	 * @param cert The certificate
	 * @return
	 */
	public static String getStatus(final XmlDom cert) {

		final String status = cert.getValue("./TrustedServiceProvider/Status/text()");
		return status;
	}

	/**
	 * This method returns the start date of the associated TSP service.
	 *
	 * @param cert The certificate
	 * @return
	 */
	public static Date getStartDate(final XmlDom cert) {

		final Date startDate = cert.getTimeValue("./TrustedServiceProvider/StartDate/text()");
		return startDate;
	}

	/**
	 * This method returns the end date of the associated TSP service.
	 *
	 * @param cert The certificate
	 * @return
	 */
	public static Date getEndDate(final XmlDom cert) {

		final Date endDate = cert.getTimeValue("./TrustedServiceProvider/EndDate/text()");
		return endDate;
	}

	/**
	 * This function returns the list of qualifiers for the given certificate.
	 *
	 * @param certificate The certificate
	 * @return the {@code List} of qualifiers or an empty list if the certificate is null.
	 */
	public static List<String> getQualifiers(final XmlDom certificate) {

		if (certificate == null) {

			return new ArrayList<String>();
		}
		final List<XmlDom> qualifiersDomList = certificate.getElements("./TrustedServiceProvider/Qualifiers/Qualifier");
		final List<String> qualifiers = XmlDom.convertToStringList(qualifiersDomList);
		return qualifiers;

	}

	public static boolean isQC_NO_SSCD(final List<String> qualifiers) {

		final boolean is = qualifiers.contains(TSLConstant.QC_NO_SSCD) || qualifiers.contains(TSLConstant.QC_NO_SSCD_119612);
		return is;
	}

	public static boolean isQC_FOR_LEGAL_PERSON(final List<String> qualifiers) {

		final boolean is = qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON) || qualifiers.contains(TSLConstant.QC_FOR_LEGAL_PERSON_119612);
		return is;
	}

	public static boolean isQCSSCD_STATUS_AS_IN_CERT(final List<String> qualifiers) {

		final boolean is = qualifiers.contains(TSLConstant.QCSSCD_STATUS_AS_IN_CERT) || qualifiers.contains(TSLConstant.QCSSCD_STATUS_AS_IN_CERT_119612);
		return is;
	}

	public static boolean isSERVICE_STATUS_UNDERSUPERVISION(final String status) {

		final boolean is = TSLConstant.SERVICE_STATUS_UNDERSUPERVISION.equals(status) || TSLConstant.SERVICE_STATUS_UNDERSUPERVISION_119612.equals(status);
		return is;
	}

	public static boolean isSERVICE_STATUS_SUPERVISIONINCESSATION(final String status) {

		final boolean is = TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION.equals(status) || TSLConstant.SERVICE_STATUS_SUPERVISIONINCESSATION_119612.equals(status);
		return is;
	}

	public static boolean isSERVICE_STATUS_ACCREDITED(final String status) {

		final boolean is = TSLConstant.SERVICE_STATUS_ACCREDITED.equals(status) || TSLConstant.SERVICE_STATUS_ACCREDITED_119612.equals(status);
		return is;
	}
}
