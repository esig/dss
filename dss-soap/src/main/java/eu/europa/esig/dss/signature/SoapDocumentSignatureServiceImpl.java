package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.ToBeSigned;

@SuppressWarnings("serial")
public class SoapDocumentSignatureServiceImpl implements SoapDocumentSignatureService {

	private RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> service;

	public void setService(RemoteDocumentSignatureService<RemoteDocument, RemoteSignatureParameters> service) {
		this.service = service;
	}

	@Override
	public ToBeSigned getDataToSign(DataToSignOneDocumentDTO dataToSignDto) throws DSSException {
		return service.getDataToSign(dataToSignDto.getToSignDocument(), dataToSignDto.getParameters());
	}

	@Override
	public RemoteDocument signDocument(SignOneDocumentDTO signDocumentDto) throws DSSException {
		return toRemoteDocument(
				service.signDocument(signDocumentDto.getToSignDocument(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue()));
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) throws DSSException {
		return toRemoteDocument(service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters()));
	}

	private RemoteDocument toRemoteDocument(DSSDocument doc) throws DSSException {
		return new RemoteDocument(DSSUtils.toByteArray(doc), doc.getMimeType(), doc.getName());
	}

}
