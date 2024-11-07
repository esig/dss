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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Checks if all certificates in the path have the corresponding signing certificate references
 */
public class AllCertificatesInPathReferencedCheck extends ChainItem<XmlSAV> {

	/** The token to check */
	private final TokenProxy token;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlSAV}
	 * @param token {@link TokenProxy}
	 * @param constraint {@link LevelConstraint}
	 */
	public AllCertificatesInPathReferencedCheck(I18nProvider i18nProvider, XmlSAV result, TokenProxy token,
												LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		List<RelatedCertificateWrapper> relatedSigningCertificates = token.foundCertificates()
				.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		List<String> signingCertificateIds = relatedSigningCertificates.stream().map(CertificateWrapper::getId).collect(Collectors.toList());

		for (CertificateWrapper certificate : token.getCertificateChain()) {
			if (!signingCertificateIds.contains(certificate.getId())) {
				// certificate in the certificate path is not covered by a signing certificate reference
				return false;
			}
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_SAV_ACPCCRSCA;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_SAV_ACPCCRSCA_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CONSTRAINTS_FAILURE;
	}
	
}
