package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * Validates the result of a cryptographic checker
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class CryptographicCheckerResultCheck<T extends XmlConstraintsConclusion> extends AbstractCryptographicCheckerResultCheck<T> {

	/** The validated token */
	private final TokenProxy token;

	/** Validation time */
	private final Date validationDate;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param token {@link TokenProxy}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param ccResult {@link XmlCC}
	 * @param constraint {@link LevelConstraint}
	 */
	public CryptographicCheckerResultCheck(I18nProvider i18nProvider, T result, TokenProxy token, Date validationDate,
										   MessageTag position, XmlCC ccResult, LevelConstraint constraint) {
		super(i18nProvider, result, position, ccResult, constraint);
		this.token = token;
		this.validationDate = validationDate;
	}
	
	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (isValid(ccResult)) {
			return i18nProvider.getMessage(MessageTag.VALIDATION_TIME, dateTime);
		} else {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE, getErrorMessage(), token.getId(), dateTime);
		}
	}

}
