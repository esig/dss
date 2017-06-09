package eu.europa.esig.dss.token;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.RemoteCertificate;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.x509.CertificateToken;

public class RemoteSignatureTokenConnectionImpl implements RemoteSignatureTokenConnection {

	private AbstractKeyStoreTokenConnection token;

	public void setToken(AbstractKeyStoreTokenConnection token) {
		this.token = token;
	}

	@Override
	public List<RemoteKeyEntry> getKeys() throws DSSException {
		List<RemoteKeyEntry> result = new ArrayList<RemoteKeyEntry>();
		List<DSSPrivateKeyEntry> keys = new ArrayList<DSSPrivateKeyEntry>();
		try {
			keys = token.getKeys();
		} finally {
			token.close();
		}

		for (DSSPrivateKeyEntry keyEntry : keys) {
			result.add(convert((KSPrivateKeyEntry) keyEntry));
		}
		return result;
	}

	@Override
	public RemoteKeyEntry getKey(String alias) throws DSSException {
		KSPrivateKeyEntry key = null;
		try {
			key = token.getKey(alias);
		} finally {
			token.close();
		}
		return convert(key);
	}

	@Override
	public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, String alias) throws DSSException {
		SignatureValue signatureValue = null;
		try {
			DSSPrivateKeyEntry key = token.getKey(alias);
			signatureValue = token.sign(toBeSigned, digestAlgorithm, key);
		} finally {
			token.close();
		}
		return signatureValue;
	}

	private RemoteKeyEntry convert(KSPrivateKeyEntry key) {
		if (key == null) {
			return null;
		}

		RemoteKeyEntry dto = new RemoteKeyEntry();
		dto.setAlias(key.getAlias());
		dto.setEncryptionAlgo(key.getEncryptionAlgorithm());
		dto.setCertificate(getRemoteCertificate(key.getCertificate()));

		CertificateToken[] certificateChain = key.getCertificateChain();
		if (certificateChain != null) {
			RemoteCertificate[] dtos = new RemoteCertificate[certificateChain.length];
			int i = 0;
			for (CertificateToken certificateToken : certificateChain) {
				dtos[i] = getRemoteCertificate(certificateToken);
				i++;
			}
			dto.setCertificateChain(dtos);
		}

		return dto;
	}

	private RemoteCertificate getRemoteCertificate(CertificateToken certificate) {
		RemoteCertificate dto = new RemoteCertificate();
		dto.setEncodedCertificate(certificate.getEncoded());
		return dto;
	}

}
