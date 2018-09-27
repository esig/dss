package eu.europa.esig.dss.token;

import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

public class SoapSignatureTokenConnectionImpl implements SoapSignatureTokenConnection {

	private RemoteSignatureTokenConnection token;

	public void setToken(RemoteSignatureTokenConnection token) {
		this.token = token;
	}

	@Override
	public List<RemoteKeyEntry> getKeys() throws DSSException {
		return token.getKeys();
	}

	@Override
	public RemoteKeyEntry getKey(String alias) throws DSSException {
		return token.getKey(alias);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException {
		return token.sign(toBeSigned, digestAlgorithm, alias);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, MaskGenerationFunction mgf, String alias) throws DSSException {
		return token.sign(toBeSigned, digestAlgorithm, mgf, alias);
	}

}
