package eu.europa.esig.dss.token;

import java.util.List;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.MaskGenerationFunction;
import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;

@WebService
public interface SoapSignatureTokenConnection extends RemoteSignatureTokenConnection {

	@Override
	@WebMethod(operationName = "getKeys")
	@WebResult(name = "response")
	List<RemoteKeyEntry> getKeys() throws DSSException;

	@Override
	@WebMethod(operationName = "getKey")
	@WebResult(name = "response")
	RemoteKeyEntry getKey(@WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "sign")
	@WebResult(name = "response")
	SignatureValue sign(@WebParam(name = "toBeSigned") ToBeSigned toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "alias") String alias) throws DSSException;

	@Override
	@WebMethod(operationName = "signWithMask")
	@WebResult(name = "response")
	SignatureValue sign(@WebParam(name = "toBeSigned") ToBeSigned toBeSigned, @WebParam(name = "digestAlgorithm") DigestAlgorithm digestAlgorithm,
			@WebParam(name = "maskGenerationFunction") MaskGenerationFunction mgf, @WebParam(name = "alias") String alias) throws DSSException;

}
