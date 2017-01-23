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
package eu.europa.esig.dss.validation.process.qmatrix.qualification.checks;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public final class ServiceQualification {

	private ServiceQualification() {
	}

	public static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";

	/**
	 * QCStatement ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"): to indicate that all certificates
	 * identified by the applicable list of criteria are issued as qualified certificates.
	 */
	public static final String QC_STATEMENT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement";

	/**
	 * NotQualified ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified"): to indicate that no
	 * certificates
	 * identified by the applicable list of criteria are to be considered as qualified certificates.
	 */
	public static final String NOT_QUALIFIED = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified";

	/**
	 * QCWithSSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, have their
	 * private key residing in an SSCD
	 */
	public static final String QC_WITH_SSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD";

	/**
	 * QCWithQSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, have their
	 * private key residing in a QSCD
	 */
	public static final String QC_WITH_QSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD";

	/**
	 * QCNoSSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, do not have
	 * their private key residing in an SSCD
	 */
	public static final String QC_NO_SSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD";

	/**
	 * QCNoQSCD ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, do not have
	 * their private key residing in a QSCD
	 */
	public static final String QC_NO_QSCD = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD";

	/**
	 * QCSSCDStatusAsInCert ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert"): to indicate
	 * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
	 * qualified, do contain proper machine processable information about whether or not their private key residing in
	 * an SSCD;
	 */
	public static final String QC_SSCD_STATUS_AS_IN_CERT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert";

	/**
	 * QCQSCDStatusAsInCert ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"): to indicate
	 * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
	 * qualified, do contain proper machine processable information about whether or not their private key residing in a
	 * QSCD;
	 */
	public static final String QC_QSCD_STATUS_AS_IN_CERT = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert";

	/**
	 * QCQSCDManagedOnBehalf ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"): to indicate
	 * that all certificates identified by the applicable list of criteria, when they are claimed or stated as being
	 * qualified, have their private key residing in a QSCD for which the generation and management of that private key
	 * is done by the qualified TSP on behalf of the entity whose identity is certified in the certificate;
	 */
	public static final String QC_QSCD_MANAGED_ON_BEHALF = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf";

	/**
	 * QCForLegalPerson("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"): to indicate that all
	 * certificates identified by the applicable list of criteria, when they are claimed or stated as being qualified,
	 * are issued to legal persons;
	 */
	public static final String QC_FOR_LEGAL_PERSON = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson";

	/**
	 * QCForESig ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
	 * electronic signatures;
	 */
	public static final String QC_FOR_ESIG = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig";

	/**
	 * QCForESeal ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
	 * electronic seals;
	 */
	public static final String QC_FOR_ESEAL = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal";

	/**
	 * QCForWSA ("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"): to indicate that all certificates
	 * identified by the applicable list of criteria, when they are claimed or stated as being qualified, are issued for
	 * web site authentication;
	 */
	public static final String QC_FOR_WSA = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA";

	public static boolean isCaQc(String serviceType) {
		return CA_QC.equals(serviceType);
	}

	public static boolean isQcStatement(List<String> qualifiers) {
		return listContains(qualifiers, QC_STATEMENT);
	}

	public static boolean isNotQualified(List<String> qualifiers) {
		return listContains(qualifiers, NOT_QUALIFIED);
	}

	public static boolean isQcNoQSCD(List<String> qualifiers) {
		return listContains(qualifiers, QC_NO_QSCD, QC_NO_SSCD);
	}

	public static boolean isQcForLegalPerson(List<String> qualifiers) {
		return listContains(qualifiers, QC_FOR_LEGAL_PERSON);
	}

	public static boolean isQcQSCDStatusAsInCert(List<String> qualifiers) {
		return listContains(qualifiers, QC_QSCD_STATUS_AS_IN_CERT, QC_SSCD_STATUS_AS_IN_CERT);
	}

	public static boolean isQcQSCDManagedOnBehalf(List<String> qualifiers) {
		return listContains(qualifiers, QC_QSCD_MANAGED_ON_BEHALF);
	}

	public static boolean isQcWithQSCD(List<String> qualifiers) {
		return listContains(qualifiers, QC_WITH_QSCD, QC_WITH_SSCD);
	}

	public static boolean isQcForEsig(List<String> qualifiers) {
		return listContains(qualifiers, QC_FOR_ESIG);
	}

	public static boolean isQcForEseal(List<String> qualifiers) {
		return listContains(qualifiers, QC_FOR_ESEAL);
	}

	public static boolean isQcForWSA(List<String> qualifiers) {
		return listContains(qualifiers, QC_FOR_WSA);
	}

	public static List<String> getUsageQualifiers(List<String> qualifiers) {
		List<String> filteredQualifiers = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(qualifiers)) {
			if (qualifiers.contains(QC_FOR_ESIG)) {
				filteredQualifiers.add(QC_FOR_ESIG);
			}
			if (qualifiers.contains(QC_FOR_ESEAL)) {
				filteredQualifiers.add(QC_FOR_ESEAL);
			}
			if (qualifiers.contains(QC_FOR_WSA)) {
				filteredQualifiers.add(QC_FOR_WSA);
			}
		}
		return filteredQualifiers;
	}

	private static boolean listContains(List<String> qualifiers, String... expecteds) {
		if (Utils.isCollectionNotEmpty(qualifiers)) {
			for (String expected : expecteds) {
				if (qualifiers.contains(expected)) {
					return true;
				}
			}
		}
		return false;
	}
}