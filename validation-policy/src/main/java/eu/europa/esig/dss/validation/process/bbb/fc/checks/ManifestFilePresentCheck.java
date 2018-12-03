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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class ManifestFilePresentCheck extends ChainItem<XmlFC> {

	private final XmlContainerInfo containerInfo;

	private MessageTag message;
	private MessageTag error;

	public ManifestFilePresentCheck(XmlFC result, XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(result, constraint);
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		if ("ASiC-S".equals(containerInfo.getContainerType())) { // ASiC-S no Manifest
			message = MessageTag.BBB_FC_IMFP_ASICS;
			error = MessageTag.BBB_FC_IMFP_ASICS_ANS;
			return Utils.isCollectionEmpty(containerInfo.getManifestFiles());
		} else { // ASiC-E one or more manifest
			message = MessageTag.BBB_FC_IMFP_ASICE;
			error = MessageTag.BBB_FC_IMFP_ASICE_ANS;
			return Utils.isCollectionNotEmpty(containerInfo.getManifestFiles());
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return message;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return error;
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
