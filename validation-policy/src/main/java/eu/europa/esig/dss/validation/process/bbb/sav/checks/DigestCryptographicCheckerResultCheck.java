package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public class DigestCryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheckerResultCheck<T> {

	private final Date validationDate;
	private final String referenceName;

	public DigestCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate, MessageTag position, 
			XmlCC ccResult, LevelConstraint constraint) {
		this(i18nProvider, result, validationDate, position, null, ccResult, constraint);
	}

	public DigestCryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, Date validationDate, MessageTag position, String referenceName, 
			XmlCC ccResult, LevelConstraint constraint) {
		super(i18nProvider, result, position, ccResult, constraint);
		this.validationDate = validationDate;
		this.referenceName = referenceName;
	}
	
	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (isValid(ccResult)) {
			if (Utils.isStringNotEmpty(referenceName)) {
				return i18nProvider.getMessage(MessageTag.VALIDATION_TIME_DM_WITH_NAME, dateTime, position, referenceName);
			} else {
				return i18nProvider.getMessage(MessageTag.VALIDATION_TIME_DM, dateTime, position);
			}
		} else {
			if (Utils.isStringNotEmpty(referenceName)) {
				return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF_WITH_NAME, getErrorMessage(), referenceName, dateTime);
			} else {
				return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_REF, getErrorMessage(), dateTime);
			}
		}
	}

}
