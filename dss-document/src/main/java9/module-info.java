module jpms_dss_document {
	exports eu.europa.esig.dss;
	exports eu.europa.esig.dss.definition;
	exports eu.europa.esig.dss.definition.xmldsig;
	exports eu.europa.esig.dss.signature;
	exports eu.europa.esig.dss.validation;
	exports eu.europa.esig.dss.validation.policy;
	exports eu.europa.esig.dss.validation.scope;
	exports eu.europa.esig.dss.validation.timestamp;

    uses eu.europa.esig.dss.validation.DocumentValidatorFactory;
    uses eu.europa.esig.dss.validation.policy.SignaturePolicyValidator;
    

    provides eu.europa.esig.dss.validation.DocumentValidatorFactory with eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidatorFactory;

}