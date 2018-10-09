package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.ToBeSigned;

@SuppressWarnings("serial")
public class RestDocumentSignatureServiceImpl implements RestDocumentSignatureService {

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
		return service.signDocument(signDocumentDto.getToSignDocument(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue());
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) throws DSSException {
		return service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters());
	}

}
