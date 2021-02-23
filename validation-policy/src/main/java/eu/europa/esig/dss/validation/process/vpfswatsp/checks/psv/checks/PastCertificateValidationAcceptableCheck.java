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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the Past Certificate Validation result is acceptable
 */
public class PastCertificateValidationAcceptableCheck extends ChainItem<XmlPSV> {

	/** Past Certificate Validation */
	private final XmlPCV pcv;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlPSV}
	 * @param pcv {@link XmlPCV}
	 * @param tokenId {@link String}
	 * @param constraint {@link LevelConstraint}
	 */
	public PastCertificateValidationAcceptableCheck(I18nProvider i18nProvider, XmlPSV result, XmlPCV pcv, String tokenId,
													LevelConstraint constraint) {
		super(i18nProvider, result, constraint, tokenId);
		this.pcv = pcv;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.PCV;
	}

	@Override
	protected boolean process() {
		if ((pcv != null) && (pcv.getConclusion() != null)) {
			Indication pcvIndication = pcv.getConclusion().getIndication();
			SubIndication pcvSubindication = pcv.getConclusion().getSubIndication();

			// INDETERMINATE cases are treated in following steps depending of POE
			return Indication.PASSED.equals(pcvIndication)
					|| (Indication.INDETERMINATE.equals(pcvIndication) && (SubIndication.REVOKED_NO_POE.equals(pcvSubindication)
							|| SubIndication.REVOKED_CA_NO_POE.equals(pcvSubindication) || SubIndication.OUT_OF_BOUNDS_NO_POE.equals(pcvSubindication)
							|| SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(pcvSubindication)));

		}
		return false;

	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PSV_IPCVA;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PSV_IPCVA_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return pcv.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return pcv.getConclusion().getSubIndication();
	}

}
