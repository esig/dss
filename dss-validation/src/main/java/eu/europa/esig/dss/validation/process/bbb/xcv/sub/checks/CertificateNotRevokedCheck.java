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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if the certificate is not revokek
 */
public class CertificateNotRevokedCheck extends ChainItem<XmlSubXCV> {

	/** Certificate's revocation */
	private final CertificateRevocationWrapper certificateRevocation;

	/** Validation time */
	private final Date currentTime;

	/** SubContext */
	private final SubContext subContext;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlSubXCV}
	 * @param certificateRevocation {@link CertificateRevocationWrapper}
	 * @param currentTime {@link Date}
	 * @param constraint {@link LevelRule}
	 * @param subContext {@link SubContext}
	 */
	public CertificateNotRevokedCheck(I18nProvider i18nProvider, XmlSubXCV result,
									  CertificateRevocationWrapper certificateRevocation, Date currentTime,
									  LevelRule constraint, SubContext subContext) {
		super(i18nProvider, result, constraint);
		this.certificateRevocation = certificateRevocation;
		this.currentTime = currentTime;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		boolean isRevoked = (certificateRevocation != null) && certificateRevocation.isRevoked()
				&& !RevocationReason.CERTIFICATE_HOLD.equals(certificateRevocation.getReason());
		if (isRevoked) {
			isRevoked = certificateRevocation.getRevocationDate() != null && currentTime.compareTo(certificateRevocation.getRevocationDate()) >= 0;
		}
		return !isRevoked;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (certificateRevocation != null && certificateRevocation.getRevocationDate() != null) {
			String revocationDateStr = ValidationProcessUtils.getFormattedDate(certificateRevocation.getRevocationDate());
			return i18nProvider.getMessage(MessageTag.REVOCATION_REASON, certificateRevocation.getReason(), revocationDateStr);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCR;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_ISCR_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		if (SubContext.SIGNING_CERT.equals(subContext)) {
			return SubIndication.REVOKED_NO_POE;
		} else {
			return SubIndication.REVOKED_CA_NO_POE;
		}
	}

}
