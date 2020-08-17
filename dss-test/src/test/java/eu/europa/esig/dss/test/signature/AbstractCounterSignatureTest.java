package eu.europa.esig.dss.test.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import javax.xml.bind.JAXBElement;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.validationreport.jaxb.SACommitmentTypeIndicationType;
import eu.europa.esig.validationreport.jaxb.SACounterSignatureType;
import eu.europa.esig.validationreport.jaxb.SASignatureProductionPlaceType;
import eu.europa.esig.validationreport.jaxb.SASignerRoleType;
import eu.europa.esig.validationreport.jaxb.SignatureAttributesType;
import eu.europa.esig.validationreport.jaxb.VOReferenceType;

public abstract class AbstractCounterSignatureTest<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters, 
				CSP extends SerializableCounterSignatureParameters> extends AbstractPkiFactoryTestDocumentSignatureService<SP, TP> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCounterSignatureTest.class);
	
	protected abstract CSP getCounterSignatureParameters();

	protected abstract CounterSignatureService<CSP> getCounterSignatureService();
	
	private String signatureId;
	
	@Override
	@Test
	public void signAndVerify() {
		final DSSDocument signedDocument = sign();

		SignedDocumentValidator validator = getValidator(signedDocument);

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertTrue(Utils.isCollectionNotEmpty(signatures));
		
		AdvancedSignature signature = signatures.get(signatures.size() - 1);
		signatureId = signature.getId();
		
		DSSDocument counterSigned = counterSign(signedDocument, getSignatureIdToCounterSign());

		assertNotNull(counterSigned.getName());
		assertNotNull(DSSUtils.toByteArray(counterSigned));
		assertNotNull(counterSigned.getMimeType());

		// counterSigned.save("target/" + counterSigned.getName());

		byte[] byteArray = DSSUtils.toByteArray(counterSigned);
		onDocumentSigned(byteArray);
		if (LOG.isDebugEnabled()) {
			LOG.debug(new String(byteArray));
		}

		checkMimeType(counterSigned);
		
		verify(counterSigned);
	}
	
	protected DSSDocument counterSign(DSSDocument signatureDocument, String signatureId) {
		CSP counterSignatureParameters = getCounterSignatureParameters();
		counterSignatureParameters.setSignatureIdToCounterSign(signatureId);
		
		CounterSignatureService<CSP> counterSignatureService = getCounterSignatureService();
		
		ToBeSigned dataToSign = counterSignatureService.getDataToBeCounterSigned(signatureDocument, counterSignatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, counterSignatureParameters.getDigestAlgorithm(),
				counterSignatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
		return counterSignatureService.counterSignSignature(signatureDocument, counterSignatureParameters, signatureValue);
	}

	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		assertEquals(2, Utils.collectionSize(diagnosticData.getSignatureIdList()));
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		String counterSignatureId = getSignatureIdToCounterSign();
		
		boolean counterSignatureFound = false;
		for (AdvancedSignature signature : signatures) {
			if (counterSignatureId.equals(signature.getId())) {
				List<AdvancedSignature> counterSignatures = signature.getCounterSignatures();
				assertTrue(Utils.isCollectionNotEmpty(signature.getCounterSignatures()));
				for (AdvancedSignature counterSignature : counterSignatures) {
					AdvancedSignature masterSignature = counterSignature.getMasterSignature();
					assertNotNull(masterSignature);
					assertEquals(counterSignatureId, masterSignature.getId());
					counterSignatureFound = true;
				}
			}
		}
		assertTrue(counterSignatureFound);
	}
	
	@Override
	protected void validateETSISignatureAttributes(SignatureAttributesType signatureAttributes) {
		List<Object> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (Object signatureAttributeObj : signatureAttributeObjects) {
			if (signatureAttributeObj instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) signatureAttributeObj;
				Object value = jaxbElement.getValue();
				
				if (value instanceof SACommitmentTypeIndicationType) {
					SACommitmentTypeIndicationType commitment = (SACommitmentTypeIndicationType) value;
					SerializableSignatureParameters signatureParameters = hasCounterSignature(signatureAttributes) ? 
							getSignatureParameters() : getCounterSignatureParameters();
					validateETSICommitment(commitment, signatureParameters);
				} else if (value instanceof SASignerRoleType) {
					SASignerRoleType signerRoles = (SASignerRoleType) value;
					validateETSISASignerRoleType(signerRoles);
				} else if (value instanceof SASignatureProductionPlaceType) {
					SASignatureProductionPlaceType productionPlace = (SASignatureProductionPlaceType) value;
					validateETSISASignatureProductionPlaceType(productionPlace);
				}
			}
		}
	}
	
	protected boolean hasCounterSignature(SignatureAttributesType signatureAttributes) {
		List<Object> signatureAttributeObjects = signatureAttributes.getSigningTimeOrSigningCertificateOrDataObjectFormat();
		for (Object signatureAttributeObj : signatureAttributeObjects) {
			if (signatureAttributeObj instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) signatureAttributeObj;
				Object value = jaxbElement.getValue();
				
				if (value instanceof SACounterSignatureType) {
					// TODO multiple value -> multiple tag in signatureattributes ??
					SACounterSignatureType counterSignature = (SACounterSignatureType) value;
					List<VOReferenceType> attributeObject = counterSignature.getAttributeObject();
					assertTrue(Utils.isCollectionNotEmpty(attributeObject));
					assertNotNull(counterSignature.getCounterSignature());
					assertNotNull(counterSignature.getCounterSignature().getDigestMethod());
					assertNotNull(counterSignature.getCounterSignature().getDigestValue());
					
					return true;
				}
			}
		}
		return false;
	}

	protected String getSignatureIdToCounterSign() {
		return signatureId;
	}

}
