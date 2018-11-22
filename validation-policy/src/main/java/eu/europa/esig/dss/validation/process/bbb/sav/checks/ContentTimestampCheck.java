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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TimestampWrapper;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ContentTimestampCheck extends ChainItem<XmlSAV> {

	private final DiagnosticData diagnosticData;
	private final SignatureWrapper signature;

	public ContentTimestampCheck(XmlSAV result, DiagnosticData diagnosticData, SignatureWrapper signature, LevelConstraint constraint) {
		super(result, constraint);
		this.diagnosticData = diagnosticData;
		this.signature = signature;
	}

	@Override
	protected boolean process() {
		List<TimestampWrapper> timestampsBySignature = diagnosticData.getTimestampList(signature.getId());

		for (TimestampWrapper timestampWrapper : timestampsBySignature) {
			if (TimestampType.CONTENT_TIMESTAMP.name().equals(timestampWrapper.getType())
					|| TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.name().equals(timestampWrapper.getType())
					|| TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.name().equals(timestampWrapper.getType())) {
				return true;
			}
		}

		return false;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTSIP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ISQPCTSIP_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}

}
