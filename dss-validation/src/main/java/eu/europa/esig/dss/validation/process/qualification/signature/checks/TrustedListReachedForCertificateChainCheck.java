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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Checks whether a Trusted List has been reached for the given certificate chain
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class TrustedListReachedForCertificateChainCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** End-entity certificate */
	private final CertificateWrapper signingCertificate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlConstraintsConclusion}
	 * @param signingCertificate {@link CertificateWrapper}
	 * @param constraint {@link LevelRule}
	 */
	public TrustedListReachedForCertificateChainCheck(I18nProvider i18nProvider, T result, 
			CertificateWrapper signingCertificate, LevelRule constraint) {
		super(i18nProvider, result, constraint);
		this.signingCertificate = signingCertificate;
	}

	@Override
	protected boolean process() {
		return signingCertificate != null && signingCertificate.isTrustedListReached();
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_CERT_TRUSTED_LIST_REACHED_ANS;
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
