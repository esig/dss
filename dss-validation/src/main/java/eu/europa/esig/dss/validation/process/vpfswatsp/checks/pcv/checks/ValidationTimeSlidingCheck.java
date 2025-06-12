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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * Checks if the Validation Time Sliding result is valid
 */
public class ValidationTimeSlidingCheck extends ChainItem<XmlPCV> {

	/** Validation Time Sliding */
	private final XmlVTS vts;

	/** The certificate used as a trust anchor during the VTS process */
	private final CertificateWrapper trustedCertificate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlPCV}
	 * @param vts {@link XmlVTS}
	 * @param tokenId {@link String}
	 * @param trustedCertificate {@link CertificateWrapper}
	 * @param constraint {@link LevelRule}
	 */
	public ValidationTimeSlidingCheck(I18nProvider i18nProvider, XmlPCV result, XmlVTS vts, String tokenId,
									  CertificateWrapper trustedCertificate, LevelRule constraint) {
		super(i18nProvider, result, constraint, tokenId);
		this.vts = vts;
		this.trustedCertificate = trustedCertificate;
	}

	@Override
	protected XmlBlockType getBlockType() {
		return XmlBlockType.VTS;
	}

	@Override
	protected boolean process() {
		return isValid(vts);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.PCV_IVTSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.PCV_IVTSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return vts.getConclusion().getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return vts.getConclusion().getSubIndication();
	}

	@Override
	protected String buildAdditionalInfo() {
		if (vts.getControlTime() != null) {
			if (trustedCertificate != null) {
				return i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR,
						trustedCertificate.getId(), ValidationProcessUtils.getFormattedDate(vts.getControlTime()));
			} else {
				return i18nProvider.getMessage(MessageTag.CONTROL_TIME_ALONE,
						ValidationProcessUtils.getFormattedDate(vts.getControlTime()));
			}
		}
		return null;
	}

}
