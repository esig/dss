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
package eu.europa.esig.dss.validation.process.qualification.trust;

import java.util.List;

import eu.europa.esig.dss.utils.Utils;

public final class AdditionalServiceInformation {

	private AdditionalServiceInformation() {
	}

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic signatures;
	 */
	public static final String FOR_ESIGNATURES = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals": in order to further specify the
	 * "Service type identifier" identified service as being provided for electronic seals;
	 */
	public static final String FOR_ESEALS = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals";

	/**
	 * "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication": in order to further specify the
	 * "Service type identifier" identified service as being provided for web site authentication;
	 */
	public static final String FOR_WEB_AUTHENTICATION = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication";

	public static boolean isForeSignatures(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESIGNATURES);
	}

	public static boolean isForeSeals(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_ESEALS);
	}

	public static boolean isForeSealsOnly(List<String> additionalServiceInfos) {
		return Utils.collectionSize(additionalServiceInfos) == 1 && isForeSeals(additionalServiceInfos);
	}

	public static boolean isForWebAuth(List<String> additionalServiceInfos) {
		return additionalServiceInfos.contains(FOR_WEB_AUTHENTICATION);
	}

	public static boolean isForWebAuthOnly(List<String> additionalServiceInfos) {
		return Utils.collectionSize(additionalServiceInfos) == 1 && isForWebAuth(additionalServiceInfos);
	}

}
