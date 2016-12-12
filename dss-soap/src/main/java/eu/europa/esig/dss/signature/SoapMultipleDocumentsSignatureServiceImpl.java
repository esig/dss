package eu.europa.esig.dss.signature;

import java.io.IOException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.utils.Utils;

@SuppressWarnings("serial")
public class SoapMultipleDocumentsSignatureServiceImpl implements SoapMultipleDocumentsSignatureService {

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
		try {
			return new RemoteDocument(Utils.toByteArray(doc.openStream()), doc.getMimeType(), doc.getName());
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

}
