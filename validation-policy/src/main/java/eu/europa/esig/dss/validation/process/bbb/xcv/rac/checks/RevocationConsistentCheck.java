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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Checks if the revocation is consistent and can be used for the given certificate
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class RevocationConsistentCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	/** The certificate in question */
	private final CertificateWrapper certificate;

	/** Revocation data to check */
	private final RevocationWrapper revocationData;

	/** ThisUpdate of the revocation */
	private Date thisUpdate;

	/** Certificate's NotBefore */
	private Date certNotBefore;

	/** Certificate's NotAfter */
	private Date certNotAfter;

	/** Defines date after which the revocation issuer ensure the revocation is contained for the certificate */
	private Date notAfterRevoc;

	/** Defines if certHash matches */
	private boolean certHashOK;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param revocationData {@link RevocationWrapper}
	 * @param constraint {@link LevelConstraint}
	 */
	public RevocationConsistentCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificate, 
			RevocationWrapper revocationData, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificate = certificate;
		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		certNotBefore = certificate.getNotBefore();
		certNotAfter = certificate.getNotAfter();
		thisUpdate = revocationData.getThisUpdate();

		notAfterRevoc = thisUpdate;

		/*
		 * If a CRL contains the extension expiredCertsOnCRL defined in [i.12], it shall prevail over the TL
		 * extension value but only for that specific CRL.
		 */
		Date expiredCertsOnCRL = revocationData.getExpiredCertsOnCRL();
		if (expiredCertsOnCRL != null) {
			notAfterRevoc = expiredCertsOnCRL;
		}

		/*
		 * If an OCSP response contains the extension ArchiveCutoff defined in section 4.4.4 of
		 * IETF RFC 6960 [i.11], it shall prevail over the TL extension value but only for that specific OCSP
		 * response.
		 */
		Date archiveCutOff = revocationData.getArchiveCutOff();
		if (archiveCutOff != null) {
			notAfterRevoc = archiveCutOff;
		}

		/* expiredCertsRevocationInfo Extension from TL */
		if (expiredCertsOnCRL != null || archiveCutOff != null) {
			CertificateWrapper revocCert = revocationData.getSigningCertificate();
			if (revocCert != null) {
				Date expiredCertsRevocationInfo = revocCert.getCertificateTSPServiceExpiredCertsRevocationInfo();
				if (expiredCertsRevocationInfo != null && expiredCertsRevocationInfo.before(notAfterRevoc)) {
					notAfterRevoc = expiredCertsRevocationInfo;
				}
			}
		}

		/*
		 * certHash extension can be present in an OCSP Response. If present, a digest match indicates the OCSP
		 * responder knows the certificate as we have it, and so also its revocation state
		 */
		certHashOK = revocationData.isCertHashExtensionPresent() && revocationData.isCertHashExtensionMatch();

		return thisUpdate != null && certNotBefore.compareTo(thisUpdate) <= 0 && (certNotAfter.compareTo(notAfterRevoc) >= 0 || certHashOK);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRDC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRDC_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.TRY_LATER;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (thisUpdate == null) {
			return i18nProvider.getMessage(MessageTag.REVOCATION_NO_THIS_UPDATE, revocationData.getId());
		} else if (!certNotBefore.before(thisUpdate)) {
			return i18nProvider.getMessage(MessageTag.REVOCATION_THIS_UPDATE_BEFORE, revocationData.getId(), ValidationProcessUtils.getFormattedDate(
					thisUpdate), ValidationProcessUtils.getFormattedDate(certNotBefore), ValidationProcessUtils.getFormattedDate(certNotAfter));
		} else if (certNotAfter.compareTo(notAfterRevoc) < 0 && !certHashOK) {
			return i18nProvider.getMessage(MessageTag.REVOCATION_NOT_AFTER_AFTER, revocationData.getId(), ValidationProcessUtils.getFormattedDate(
					notAfterRevoc), ValidationProcessUtils.getFormattedDate(certNotBefore), ValidationProcessUtils.getFormattedDate(certNotAfter));
		} else if (certHashOK) {
			return i18nProvider.getMessage(MessageTag.REVOCATION_CERT_HASH_OK, revocationData.getId());
		} else {
			return i18nProvider.getMessage(MessageTag.REVOCATION_CONSISTENT, revocationData.getId(), ValidationProcessUtils.getFormattedDate(
					thisUpdate), ValidationProcessUtils.getFormattedDate(certNotBefore), ValidationProcessUtils.getFormattedDate(certNotAfter));
		}
	}

}
