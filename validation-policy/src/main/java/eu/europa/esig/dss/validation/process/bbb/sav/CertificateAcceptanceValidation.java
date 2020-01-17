package eu.europa.esig.dss.validation.process.bbb.sav;

import java.util.Date;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class CertificateAcceptanceValidation extends AbstractAcceptanceValidation<CertificateWrapper> {

    public CertificateAcceptanceValidation(I18nProvider i18nProvider, Date currentTime, CertificateWrapper certificateWrapper,
            ValidationPolicy validationPolicy) {
        super(i18nProvider, certificateWrapper, currentTime, Context.CERTIFICATE, validationPolicy);
    }
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
	}

    @Override
    protected void initChain() {
        firstItem = cryptographic();
    }

}
