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
package eu.europa.esig.dss.validation.process.qualification.certificate;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCertificate;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

/**
 * Verifies whether the BasicBuildingBlock's validation succeeded
 *
 */
public class AcceptableBuildingBlockConclusionCheck extends ChainItem<XmlCertificate> {

	/** BasicBuildingBlock's validation conclusion */
	private final XmlConclusion buildingBlockConclusion;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlCertificate}
	 * @param buildingBlockConclusion {@link XmlConclusion} to verify
	 * @param constraint {@link LevelConstraint}
	 */
	public AcceptableBuildingBlockConclusionCheck(I18nProvider i18nProvider, XmlCertificate result,
												  XmlConclusion buildingBlockConclusion, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.buildingBlockConclusion = buildingBlockConclusion;
	}

	@Override
	protected boolean process() {
		return isValidConclusion(buildingBlockConclusion);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ACCEPT;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ACCEPT_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return buildingBlockConclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return buildingBlockConclusion.getSubIndication();
	}

}
