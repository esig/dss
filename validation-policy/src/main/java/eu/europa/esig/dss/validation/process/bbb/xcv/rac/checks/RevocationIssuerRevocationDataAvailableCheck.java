package eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataAvailableCheck;

public class RevocationIssuerRevocationDataAvailableCheck extends RevocationDataAvailableCheck<XmlRAC> {

	public RevocationIssuerRevocationDataAvailableCheck(I18nProvider i18nProvider, XmlRAC result, CertificateWrapper certificate, LevelConstraint constraint) {
		super(i18nProvider, result, certificate, constraint);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_IRDPFRC;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_XCV_IRDPFRC_ANS;
	}

}
