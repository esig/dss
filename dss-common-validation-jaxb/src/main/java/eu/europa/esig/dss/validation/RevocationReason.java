package eu.europa.esig.dss.validation;

public enum RevocationReason {

	unspecified,

	keyCompromise,

	cACompromise,

	affiliationChanged,

	superseded,

	cessationOfOperation,

	certificateHold,

	unknow,

	removeFromCRL,

	privilegeWithdrawn,

	aACompromise;

}
