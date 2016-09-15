package eu.europa.esig.dss.validation.reports.wrapper;

import java.util.List;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;

public interface TokenProxy {

	boolean isReferenceDataFound();

	boolean isReferenceDataIntact();

	boolean isSignatureIntact();

	boolean isSignatureValid();

	String getDigestAlgoUsedToSignThisToken();

	DigestAlgorithm getDigestAlgorithm();

	EncryptionAlgorithm getEncryptionAlgorithm();

	String getEncryptionAlgoUsedToSignThisToken();

	String getKeyLengthUsedToSignThisToken();

	boolean isIssuerSerialMatch();

	boolean isAttributePresent();

	boolean isDigestValueMatch();

	boolean isDigestValuePresent();

	String getSigningCertificateId();

	String getSigningCertificateSigned();

	String getLastChainCertificateId();

	String getFirstChainCertificateId();

	String getLastChainCertificateSource();

	String getId();

	List<XmlChainItem> getCertificateChain();

	List<String> getCertificateChainIds();

}
