/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the manifest file is present inside an ASiC container
 */
public class ManifestFilePresentCheck extends ChainItem<XmlFC> {

	/** ASiC container info */
	private final XmlContainerInfo containerInfo;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlFC}
	 * @param containerInfo {@link XmlContainerInfo}
	 * @param constraint {@link LevelRule}
	 */
	public ManifestFilePresentCheck(I18nProvider i18nProvider, XmlFC result, XmlContainerInfo containerInfo,
									LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {
		if (ASiCContainerType.ASiC_E.equals(containerInfo.getContainerType())) {
			return Utils.isCollectionNotEmpty(containerInfo.getManifestFiles());
		}
		// ASiC-S container may contain a manifest file
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_FC_IMFP_ASICE;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_FC_IMFP_ASICE_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.FORMAT_FAILURE;
	}

}
