package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import java.text.MessageFormat;
import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;

public class RevocationConsistentCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final CertificateWrapper certificate;
	private final RevocationWrapper revocationData;
	
	private Date thisUpdate;
	private Date certNotBefore;
	private Date certNotAfter;
	private Date notAfterRevoc;
	private boolean certHashOK;

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

		return thisUpdate != null && certNotBefore.before(thisUpdate) && ((certNotAfter.compareTo(notAfterRevoc) >= 0) || certHashOK);
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
	protected String getAdditionalInfo() {
		String addInfo = null;
		Object[] params = null;
		if (thisUpdate == null) {
			addInfo = AdditionalInfo.REVOCATION_NO_THIS_UPDATE;
			params = new Object[] { revocationData.getId() };
		} else if (!certNotBefore.before(thisUpdate)) {
			addInfo = AdditionalInfo.REVOCATION_THIS_UPDATE_BEFORE;
			params = new Object[] { revocationData.getId(), convertDate(thisUpdate), convertDate(certNotBefore), convertDate(certNotAfter) };
		} else if (certNotAfter.compareTo(notAfterRevoc) < 0 && !certHashOK) {
			addInfo = AdditionalInfo.REVOCATION_NOT_AFTER_AFTER;
			params = new Object[] { revocationData.getId(), convertDate(notAfterRevoc), convertDate(certNotBefore), convertDate(certNotAfter) };
		} else if (certHashOK) {
			addInfo = AdditionalInfo.REVOCATION_CERT_HASH_OK;
			params = new Object[] { revocationData.getId() };
		} else {
			addInfo = AdditionalInfo.REVOCATION_CONSISTENT;
			params = new Object[] { revocationData.getId(), convertDate(thisUpdate), convertDate(certNotBefore), convertDate(certNotAfter) };
		}
		return MessageFormat.format(addInfo, params);
	}

}
