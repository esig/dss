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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class ForeSignatureAtSigningTimeCheck extends ChainItem<XmlValidationSignatureQualification> {

	private final CertificateQualification certificateQualification;

	public ForeSignatureAtSigningTimeCheck(XmlValidationSignatureQualification result, CertificateQualification certificateQualification,
			LevelConstraint constraint) {
		super(result, constraint);

		this.certificateQualification = certificateQualification;
	}

	@Override
	protected boolean process() {
		return certificateQualification.isForEsig();
	}

	@Override
	protected String getMessageTag() {
		return "QUAL_FOR_SIGN_AT_ST";
	}

	@Override
	protected String getErrorMessageTag() {
		return "QUAL_FOR_SIGN_AT_ST_ANS";
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
