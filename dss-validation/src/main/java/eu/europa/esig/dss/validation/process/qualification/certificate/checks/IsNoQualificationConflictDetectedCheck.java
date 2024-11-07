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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationCertificateQualification;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Set;

/**
 * Verifies if there is no conflict in certificate qualification determination result
 * based on a use of different TrustServices
 *
 */
public class IsNoQualificationConflictDetectedCheck extends ChainItem<XmlValidationCertificateQualification> {

	/** Set of obtained {@code CertificateQualification}s from various TrustServices */
	private final Set<CertificateQualification> certificateQualificationsAtTime;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationCertificateQualification}
	 * @param certificateQualificationsAtTime set of {@link CertificateQualification}s
	 * @param constraint {@link LevelConstraint}
	 */
	public IsNoQualificationConflictDetectedCheck(I18nProvider i18nProvider, XmlValidationCertificateQualification result,
												  Set<CertificateQualification> certificateQualificationsAtTime, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificateQualificationsAtTime = certificateQualificationsAtTime;
	}

	@Override
	protected boolean process() {
		return Utils.collectionSize(certificateQualificationsAtTime) == 1;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (Utils.collectionSize(certificateQualificationsAtTime) > 1) {
			return i18nProvider.getMessage(MessageTag.RESULTS, certificateQualificationsAtTime.toString());
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_HAS_CONF;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.QUAL_HAS_CONF_ANS;
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
