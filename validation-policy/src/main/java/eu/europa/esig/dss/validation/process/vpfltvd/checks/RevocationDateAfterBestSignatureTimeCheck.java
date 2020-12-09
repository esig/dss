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

import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if the revocation date is after best-signature-time
 */
public class RevocationDateAfterBestSignatureTimeCheck extends ChainItem<XmlValidationProcessLongTermData> {

	/** Certificate's revocation */
	private final CertificateRevocationWrapper certificateRevocation;

	/** Best signature time */
	private final Date bestSignatureTime;

	/** Validation SubContext */
	private final SubContext subContext;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationProcessLongTermData}
	 * @param certificateRevocation {@link CertificateRevocationWrapper}
	 * @param bestSignatureTime {@link Date}
	 * @param constraint {@link LevelConstraint}
	 * @param subContext {@link SubContext}
	 */
	public RevocationDateAfterBestSignatureTimeCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result,
													 CertificateRevocationWrapper certificateRevocation,
													 Date bestSignatureTime, LevelConstraint constraint,
													 SubContext subContext) {
		super(i18nProvider, result, constraint);

		this.certificateRevocation = certificateRevocation;
		this.bestSignatureTime = bestSignatureTime;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		Date revocationDate = certificateRevocation.getRevocationDate();
		// revocation date can be null in case of unknown status
		return revocationDate != null && revocationDate.after(bestSignatureTime);
	}

	@Override
	protected String buildAdditionalInfo() {
		String bestSignatureTimeStr = bestSignatureTime == null ? " ? " : ValidationProcessUtils.getFormattedDate(bestSignatureTime);
		return i18nProvider.getMessage(MessageTag.BEST_SIGNATURE_TIME, bestSignatureTimeStr);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ADEST_IRTPTBST;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.ADEST_IRTPTBST_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		if (SubContext.SIGNING_CERT.equals(subContext))
			return SubIndication.REVOKED_NO_POE;
		else
			return SubIndication.REVOKED_CA_NO_POE;
	}

}
