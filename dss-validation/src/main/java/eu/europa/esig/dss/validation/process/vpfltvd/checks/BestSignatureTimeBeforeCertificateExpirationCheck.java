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
package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if the best-signature-time is before certificate's expiration
 *
 * @param <T> {@link XmlConstraintsConclusion}
 *
 */
public class BestSignatureTimeBeforeCertificateExpirationCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Best signature time */
	private final Date bestSignatureTime;

	/** The signing certificate */
	private final CertificateWrapper signingCertificate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param bestSignatureTime {@link Date}
	 * @param signingCertificate {@link CertificateWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public BestSignatureTimeBeforeCertificateExpirationCheck(I18nProvider i18nProvider,
															 T result,
															 Date bestSignatureTime,
															 CertificateWrapper signingCertificate,
															 LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		// inclusive by RFC 5280
		return bestSignatureTime.compareTo(signingCertificate.getNotAfter()) <= 0;
	}

	@Override
	protected String buildAdditionalInfo() {
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : ValidationProcessUtils.getFormattedDate(bestSignatureTime);
		String certNotAfter = signingCertificate.getNotAfter() == null ? " ? " : ValidationProcessUtils.getFormattedDate(signingCertificate.getNotAfter());
		return i18nProvider.getMessage(MessageTag.BEST_SIGNATURE_TIME_CERT_NOT_AFTER, bestSignatureTimeStr, certNotAfter);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_IBSTBCEC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_IBSTBCEC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.OUT_OF_BOUNDS_NOT_REVOKED;
	}

}
