package eu.europa.esig.dss.standalone.service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.RemoteCertificate;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.RemoteDocumentSignatureService;
import eu.europa.esig.dss.standalone.model.SignatureModel;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.x509.CertificateToken;

public class SignatureService {

	private RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> remoteSignatureService;

	public void setRemoteSignatureService(RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> remoteSignatureService) {
		this.remoteSignatureService = remoteSignatureService;
	}

	public DSSDocument sign(SignatureModel model, SignatureTokenConnection token, DSSPrivateKeyEntry signer) {

		RemoteDocument toSignDocument = new RemoteDocument(new FileDocument(model.getFileToSign()));

		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setDigestAlgorithm(model.getDigestAlgorithm());
		parameters.setSignatureLevel(model.getSignatureLevel());
		parameters.setSignaturePackaging(model.getSignaturePackaging());
		BLevelParameters bLevelParams = new BLevelParameters();
		bLevelParams.setSigningDate(new Date());
		parameters.setBLevelParams(bLevelParams);

		parameters.setSigningCertificate(new RemoteCertificate(signer.getCertificate().getEncoded()));
		CertificateToken[] certificateChain = signer.getCertificateChain();
		if (ArrayUtils.isNotEmpty(certificateChain)) {
			List<RemoteCertificate> certificateChainList = new ArrayList<RemoteCertificate>();
			for (CertificateToken certificateToken : certificateChain) {
				certificateChainList.add(new RemoteCertificate(certificateToken.getEncoded()));
			}
			parameters.setCertificateChain(certificateChainList);
		}

		ToBeSigned toBeSigned = remoteSignatureService.getDataToSign(toSignDocument, parameters);
		SignatureValue signatureValue = token.sign(toBeSigned, model.getDigestAlgorithm(), signer);
		DSSDocument signDocument = remoteSignatureService.signDocument(toSignDocument, parameters, signatureValue);

		return signDocument;
	}

	public SignatureTokenConnection getToken(SignatureModel model) {
		switch (model.getTokenType()) {
			case PKCS11:
				return new Pkcs11SignatureToken(model.getPkcsFile().getAbsolutePath(), model.getPassword().toCharArray());
			case PKCS12:
				return new Pkcs12SignatureToken(model.getPassword().toCharArray(), model.getPkcsFile());
			case MSCAPI:
				return new MSCAPISignatureToken();
			default:
				throw new IllegalArgumentException("Unsupported token type " + model.getTokenType());
		}
	}

}
