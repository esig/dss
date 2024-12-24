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
package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateRevocationSelectorResultCheck;

import java.util.Date;

/**
 * Checks if an acceptable revocation data exists
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class SatisfyingRevocationDataExistsCheck<T extends XmlConstraintsConclusion> extends CertificateRevocationSelectorResultCheck<T> {

	/** Concerned certificate token */
	private final CertificateWrapper certificateWrapper;

	/** The control time used to find out the revocation data */
	private final Date controlTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param crsResult {@link XmlCRS}
	 * @param certificateWrapper {@link CertificateWrapper}
	 * @param controlTime {@link Date}
	 * @param constraint {@link LevelConstraint}
	 */
	public SatisfyingRevocationDataExistsCheck(I18nProvider i18nProvider, T result, XmlCRS crsResult, CertificateWrapper certificateWrapper,
											   Date controlTime, LevelConstraint constraint) {
		super(i18nProvider, result, crsResult, constraint);
		this.certificateWrapper = certificateWrapper;
		this.controlTime = controlTime;
	}

	@Override
	protected String buildAdditionalInfo() {
		String latestAcceptableRevocationId = crsResult.getLatestAcceptableRevocationId();
		if (latestAcceptableRevocationId != null) {
			return i18nProvider.getMessage(MessageTag.CERTIFICATE_REVOCATION_FOUND, latestAcceptableRevocationId,
					certificateWrapper.getId(), ValidationProcessUtils.getFormattedDate(controlTime));
		} else {
			return i18nProvider.getMessage(MessageTag.CERTIFICATE_REVOCATION_NOT_FOUND, certificateWrapper.getId(),
					ValidationProcessUtils.getFormattedDate(controlTime));
		}
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_VTS_IRDPFC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_POE;
	}

}
