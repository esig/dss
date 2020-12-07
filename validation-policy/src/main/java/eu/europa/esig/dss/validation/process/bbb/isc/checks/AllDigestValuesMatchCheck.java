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
package eu.europa.esig.dss.validation.process.bbb.isc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;

public class AllDigestValuesMatchCheck extends ChainItem<XmlISC> {

	private final TokenProxy token;

	public AllDigestValuesMatchCheck(I18nProvider i18nProvider, XmlISC result, TokenProxy token, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.token = token;
	}

	@Override
	protected boolean process() {
		boolean isAllMatch = true;
		List<CertificateRefWrapper> signingCertificateReferences = token.getSigningCertificateReferences();
		if (Utils.isCollectionNotEmpty(signingCertificateReferences)) {
			for (CertificateRefWrapper reference : signingCertificateReferences) {
				isAllMatch &= (reference.isDigestValuePresent() && reference.isDigestValueMatch());
			}
		}
		return isAllMatch;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_ICS_ICDVVS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_ICS_ICDVVS_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
	}

}
