package eu.europa.esig.dss.signature;

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
	public ToBeSigned getDataToSign(DataToSignOneDocumentDTO dataToSignDto) {
		return service.getDataToSign(dataToSignDto.getToSignDocument(), dataToSignDto.getParameters());
	}

	@Override
	public RemoteDocument signDocument(SignOneDocumentDTO signDocumentDto) {
		return service.signDocument(signDocumentDto.getToSignDocument(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue());
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) {
		return service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters());
	}

}
