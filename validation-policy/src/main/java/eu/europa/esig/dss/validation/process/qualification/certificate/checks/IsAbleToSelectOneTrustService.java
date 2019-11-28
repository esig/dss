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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.diagnostic.TrustedServiceWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

public class IsAbleToSelectOneTrustService extends ChainItem<XmlValidationCertificateQualification> {

	private final List<TrustedServiceWrapper> trustServicesAtTime;

	public IsAbleToSelectOneTrustService(XmlValidationCertificateQualification result, List<TrustedServiceWrapper> trustServicesAtTime,
			LevelConstraint constraint) {
		super(result, constraint);

		this.trustServicesAtTime = trustServicesAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.collectionSize(trustServicesAtTime) == 1;
	}

	@Override
	protected String getMessageTag() {
		return "QUAL_HAS_ONLY_ONE";
	}

	@Override
	protected String getErrorMessageTag() {
		return "QUAL_HAS_ONLY_ONE_ANS";
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return null;
	}

}
