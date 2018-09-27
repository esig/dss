package eu.europa.esig.dss.signature;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
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
	public ToBeSigned getDataToSign(DataToSignMultipleDocumentsDTO dataToSignDto) throws DSSException {
		return service.getDataToSign(dataToSignDto.getToSignDocuments(), dataToSignDto.getParameters());
	}

	@Override
	public RemoteDocument signDocument(SignMultipleDocumentDTO signDocumentDto) throws DSSException {
		return toRemoteDocument(
				service.signDocument(signDocumentDto.getToSignDocuments(), signDocumentDto.getParameters(), signDocumentDto.getSignatureValue()));
	}

	@Override
	public RemoteDocument extendDocument(ExtendDocumentDTO extendDocumentDto) throws DSSException {
		return toRemoteDocument(service.extendDocument(extendDocumentDto.getToExtendDocument(), extendDocumentDto.getParameters()));
	}

	private RemoteDocument toRemoteDocument(DSSDocument doc) throws DSSException {
		return new RemoteDocument(DSSUtils.toByteArray(doc), doc.getMimeType(), doc.getName());
	}

}
