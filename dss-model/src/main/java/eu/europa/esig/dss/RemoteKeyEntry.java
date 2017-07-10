package eu.europa.esig.dss;

import java.io.Serializable;

@SuppressWarnings("serial")
public class RemoteKeyEntry implements Serializable {

	private String alias;
	private EncryptionAlgorithm encryptionAlgo;
	private RemoteCertificate certificate;
	private RemoteCertificate[] certificateChain;

	public String getAlias() {
		return alias;
	}

	public void setAlias(String alias) {
		this.alias = alias;
	}

	public EncryptionAlgorithm getEncryptionAlgo() {
		return encryptionAlgo;
	}

	public void setEncryptionAlgo(EncryptionAlgorithm encryptionAlgo) {
		this.encryptionAlgo = encryptionAlgo;
	}

	public RemoteCertificate getCertificate() {
		return certificate;
	}

	public void setCertificate(RemoteCertificate certificate) {
		this.certificate = certificate;
	}

	public RemoteCertificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(RemoteCertificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}

}
