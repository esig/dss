package eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class AcceptableRevocationDataAvailableCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final CertificateWrapper certificateWrapper;
	private final RevocationWrapper revocationData;
	
	public AcceptableRevocationDataAvailableCheck(I18nProvider i18nProvider, T result,
			RevocationWrapper revocationData, LevelConstraint constraint) {
		this(i18nProvider, result, null, revocationData, constraint);
	}

	public AcceptableRevocationDataAvailableCheck(I18nProvider i18nProvider, T result, CertificateWrapper certificateWrapper,
			RevocationWrapper revocationData, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.certificateWrapper = certificateWrapper;
		this.revocationData = revocationData;
	}

	@Override
	protected boolean process() {
		return revocationData != null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IARDPFC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IARDPFC_ANS;
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
	protected MessageTag getAdditionalInfo() {
		if (certificateWrapper != null) {
			return MessageTag.CERTIFICATE_ID.setArgs(certificateWrapper.getId());
		}
		return null;
	}

}
