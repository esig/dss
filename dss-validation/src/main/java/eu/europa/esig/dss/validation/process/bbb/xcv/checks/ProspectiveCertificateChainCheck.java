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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks if the certificate chain is trusted
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class ProspectiveCertificateChainCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** The certificate to check */
	private final CertificateWrapper certificate;

	/** The validation context */
	private final Context context;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param context {@link Context}
	 * @param constraint {@link LevelConstraint}
	 */
	public ProspectiveCertificateChainCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate,
											Context context, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificate = certificate;
		this.context = context;
	}

	@Override
	protected boolean process() {
		return certificate != null && (certificate.isTrusted() || certificate.isTrustedChain());
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_CCCBB;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
		case COUNTER_SIGNATURE:
			return MessageTag.BBB_XCV_CCCBB_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.BBB_XCV_CCCBB_TSP_ANS;
		case REVOCATION:
			return MessageTag.BBB_XCV_CCCBB_REV_ANS;
		default:
			return MessageTag.BBB_XCV_CCCBB_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
