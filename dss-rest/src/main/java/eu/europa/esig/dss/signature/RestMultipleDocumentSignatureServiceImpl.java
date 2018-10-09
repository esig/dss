package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.ToBeSigned;

@SuppressWarnings("serial")
public class RestMultipleDocumentSignatureServiceImpl implements RestMultipleDocumentSignatureService {

	private RemoteMultipleDocumentsSignatureService<RemoteDocument, RemoteSignatureParameters> service;

	public void setService(RemoteMultipleDocumentsSignatureService<RemoteDocument, RemoteSignatureParameters> service) {
		this.service = service;
	}

	@Override
	public ToBeSigned getDataToSign(DataToSignMultipleDocumentsDTO dataToSignDto) {
		return service.getDataToSign(dataToSignDto.getToSignDocuments(), dataToSignDto.getParameters());
	}

	@Override
	public RemoteDocument signDocument(SignMultipleDocumentDTO signDocumentDto) {
		return service.signDocument(signDocumentDto.getToSignDocuments(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue());
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) {
		return service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters());
	}

}
