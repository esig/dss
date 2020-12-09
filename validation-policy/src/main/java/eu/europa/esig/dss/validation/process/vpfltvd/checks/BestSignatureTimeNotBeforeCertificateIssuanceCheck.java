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
 * If best-signature-time is before the issuance date of the signing
 * certificate, the process shall return the indication FAILED with the
 * sub-indication NOT_YET_VALID. Otherwise, the process shall return the
 * indication and sub-indication which was returned by previous step.
 * 
 * {@code currentIndication} and {@code currentSubIndication} shall be null when
 * return of original result is not required
 */
public class BestSignatureTimeNotBeforeCertificateIssuanceCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** Best signature time */
	private final Date bestSignatureTime;

	/** The signing certificate */
	private final CertificateWrapper signingCertificate;

	/** Current Indication */
	private final Indication currentIndication;

	/** Current SubIndication */
	private final SubIndication currentSubIndication;

	/**
	 * The default constructor
	 * 
	 * @param i18nProvider       the il8n provider
	 * @param result             the result
	 * @param bestSignatureTime  the best signature time
	 * @param signingCertificate the signing certificate
	 * @param constraint         the constraint
	 */
	public BestSignatureTimeNotBeforeCertificateIssuanceCheck(I18nProvider i18nProvider, T result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, LevelConstraint constraint) {
		this(i18nProvider, result, bestSignatureTime, signingCertificate, null, null, constraint);
	}

	/**
	 * The default constructor allowing setting of returned Indication/subIndication on success result
	 *
	 * @param i18nProvider       the il8n provider
	 * @param result             the result
	 * @param bestSignatureTime  the best signature time
	 * @param signingCertificate the signing certificate
	 * @param currentIndication  {@link Indication}
	 * @param currentSubIndication {@link SubIndication}
	 * @param constraint         the constraint
	 */
	public BestSignatureTimeNotBeforeCertificateIssuanceCheck(I18nProvider i18nProvider, T result, Date bestSignatureTime,
			CertificateWrapper signingCertificate, Indication currentIndication, SubIndication currentSubIndication, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.bestSignatureTime = bestSignatureTime;
		this.signingCertificate = signingCertificate;
		this.currentIndication = currentIndication;
		this.currentSubIndication = currentSubIndication;
	}

	@Override
	protected boolean process() {
		return !bestSignatureTime.before(signingCertificate.getNotBefore());
	}

	@Override
	protected String buildAdditionalInfo() {
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : ValidationProcessUtils.getFormattedDate(bestSignatureTime);
		return i18nProvider.getMessage(MessageTag.BEST_SIGNATURE_TIME, bestSignatureTimeStr);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.TSV_IBSTAIDOSC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NOT_YET_VALID;
	}

	@Override
	protected Indication getSuccessIndication() {
		return currentIndication;
	}

	@Override
	protected SubIndication getSuccessSubIndication() {
		return currentSubIndication;
	}

}
