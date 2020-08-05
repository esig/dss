package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public abstract class AbstractCryptographicChecker extends Chain<XmlCC> {

	protected final EncryptionAlgorithm encryptionAlgorithm;
	protected final DigestAlgorithm digestAlgorithm;
	protected final MaskGenerationFunction maskGenerationFunction;
	protected final String keyLengthUsedToSignThisToken;
	protected final Date validationDate;
	
	protected final CryptographicConstraintWrapper constraintWrapper;
	protected final MessageTag position;
	
	protected AbstractCryptographicChecker(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithmn, Date validationDate, MessageTag position, 
			CryptographicConstraint constraint) {
		this(i18nProvider, null, digestAlgorithmn, null, null, validationDate, position, constraint);
	}

	protected AbstractCryptographicChecker(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgorithm, DigestAlgorithm digestAlgorithm,
			MaskGenerationFunction maskGenerationFunction, String keyLengthUsedToSignThisToken, Date validationDate, MessageTag position, CryptographicConstraint constraint) {
		super(i18nProvider, new XmlCC());
		
		this.encryptionAlgorithm = encryptionAlgorithm;
		this.digestAlgorithm = digestAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
		this.keyLengthUsedToSignThisToken = keyLengthUsedToSignThisToken;
		this.validationDate = validationDate;
		
		this.constraintWrapper = new CryptographicConstraintWrapper(constraint);
		this.position = position;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.CC;
	}

	protected boolean isExpirationDateAvailable() {
		return Utils.isMapNotEmpty(constraintWrapper.getExpirationTimes());
	}

	protected ChainItem<XmlCC> encryptionAlgorithmReliable() {
		return new EncryptionAlgorithmReliableCheck(i18nProvider, encryptionAlgorithm, result, position, constraintWrapper);
	}

	protected ChainItem<XmlCC> digestAlgorithmReliable() {
		return new DigestAlgorithmReliableCheck(i18nProvider, digestAlgorithm, result, position, constraintWrapper);
	}

	protected ChainItem<XmlCC> digestAlgorithmOnValidationTime() {
		return new DigestAlgorithmOnValidationTimeCheck(i18nProvider, digestAlgorithm, validationDate, result, position, constraintWrapper);
	}

	protected ChainItem<XmlCC> publicKeySizeKnown() {
		return new PublicKeySizeKnownCheck(i18nProvider, keyLengthUsedToSignThisToken, result, position, constraintWrapper);
	}

	protected ChainItem<XmlCC> publicKeySizeAcceptable() {
		return new PublicKeySizeAcceptableCheck(i18nProvider, encryptionAlgorithm, keyLengthUsedToSignThisToken, result, position, constraintWrapper);
	}

	protected ChainItem<XmlCC> encryptionAlgorithmOnValidationTime() {
		return new EncryptionAlgorithmOnValidationTimeCheck(i18nProvider, encryptionAlgorithm, keyLengthUsedToSignThisToken, validationDate, result, 
				position, constraintWrapper);
	}
	
	@Override
	protected void addAdditionalInfo() {
		collectErrorsWarnsInfos();
	}

}
