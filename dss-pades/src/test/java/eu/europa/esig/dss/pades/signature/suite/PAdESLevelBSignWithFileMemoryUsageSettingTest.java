package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.utils.Utils;

public class PAdESLevelBSignWithFileMemoryUsageSettingTest extends AbstractPAdESTestSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBSignWithFileMemoryUsageSettingTest.class);

	private PAdESService service;
	private PAdESSignatureParameters signatureParameters;
	private DSSDocument documentToSign;

	@BeforeEach
	void init() throws Exception {
		documentToSign = new FileDocument(new File(PAdESLevelBSignWithFileMemoryUsageSettingTest.class.getClassLoader().getResource("./big_file_26mb.pdf").toURI()));

		signatureParameters = new PAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		service = new PAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());
	}

	@Override
	protected DSSDocument sign() {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
		tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

		Pair<List<Double>, File> memoryOnlySignTuple = doAllSigns(PdfMemoryUsageSetting.memoryOnly(), tempFileResourcesHandlerBuilder);
		List<Double> memoryOnlyMemoryConsumptions = memoryOnlySignTuple.getLeft();

		attemptFreeRuntimeMemory();

		Pair<List<Double>, File> fileOnlySignTuple = doAllSigns(PdfMemoryUsageSetting.fileOnly(), tempFileResourcesHandlerBuilder);
		List<Double> fileOnlyMemoryConsumptions = fileOnlySignTuple.getLeft();

		attemptFreeRuntimeMemory();

//		assertEquals(memoryOnlyMemoryConsumptions.size(), fileOnlyMemoryConsumptions.size());
//
//		double memoryOnlyMemoryConsumptionsSum = memoryOnlyMemoryConsumptions.stream().collect(Collectors.summingDouble(a -> a));
//		double fileOnlyMemoryConsumptionsSum = fileOnlyMemoryConsumptions.stream().collect(Collectors.summingDouble(a -> a));
//		double difference = memoryOnlyMemoryConsumptionsSum - fileOnlyMemoryConsumptionsSum;
//		LOG.info("Memory Sum difference is: {}Mb", difference);
//		assertTrue(difference > 0);

		File ltaSignatureFile = fileOnlySignTuple.getRight();

		assertTrue(ltaSignatureFile.exists());

		File tempFile = null;
		try {
			tempFile = Files.createTempFile("dss", ".pdf").toFile();
			try (InputStream is = Files.newInputStream(ltaSignatureFile.toPath()); OutputStream os = Files.newOutputStream(tempFile.toPath())) {
				Utils.copy(is, os);
			}

		} catch (IOException e) {
			fail(e);
		}

		assertTrue(ltaSignatureFile.exists());

		assertNotNull(tempFile);
		assertTrue(tempFile.exists());

		tempFileResourcesHandlerBuilder.clear();

		assertFalse(ltaSignatureFile.exists());
		assertTrue(tempFile.exists());

		return new FileDocument(tempFile);
	}

	private Pair<List<Double>, File> doAllSigns(PdfMemoryUsageSetting pdfMemoryUsageSetting, TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder) {
		PAdESService service = getService();
		PAdESSignatureParameters params = getSignatureParameters();
		DSSDocument toBeSigned = getDocumentToSign();

		ArrayList<Double> memoryConsumptions = new ArrayList<>();

		IPdfObjFactory pdfObjFactory = new ServiceLoaderPdfObjFactory();
		pdfObjFactory.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
		pdfObjFactory.setPdfMemoryUsageSetting(pdfMemoryUsageSetting);
		service.setPdfObjFactory(pdfObjFactory);

		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		attemptFreeRuntimeMemory();
		double memoryBefore = getRuntimeMemoryInMegabytes();

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);

		double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryAfterGetDataToSign - memoryBefore);
		LOG.info("[{}] Memory used for getDataToSign() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryAfterGetDataToSign - memoryBefore);

		attemptFreeRuntimeMemory();
		memoryBefore = getRuntimeMemoryInMegabytes();

		SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
		assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

		double memoryAfterTokenSign = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryAfterTokenSign - memoryBefore);
		LOG.info("[{}] Memory used for token sign() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryAfterTokenSign - memoryBefore);

		attemptFreeRuntimeMemory();
		memoryBefore = getRuntimeMemoryInMegabytes();

		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		double memoryAfterSignDocument = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryAfterSignDocument - memoryBefore);
		LOG.info("[{}] Memory used for signDocument() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryAfterSignDocument - memoryBefore);

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

		attemptFreeRuntimeMemory();
		memoryBefore = getRuntimeMemoryInMegabytes();

		DSSDocument tLevelSignature = service.extendDocument(signedDocument, params);

		double memoryTLevelExtendDocument = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryTLevelExtendDocument - memoryBefore);
		LOG.info("[{}] Memory used for T-Level extendDocument() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryTLevelExtendDocument - memoryBefore);

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

		attemptFreeRuntimeMemory();
		memoryBefore = getRuntimeMemoryInMegabytes();

		DSSDocument ltLevelSignature = service.extendDocument(tLevelSignature, params);

		double memoryLTLevelExtendDocument = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryLTLevelExtendDocument - memoryBefore);
		LOG.info("[{}] Memory used for LT-Level extendDocument() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryLTLevelExtendDocument - memoryBefore);

		params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

		attemptFreeRuntimeMemory();
		memoryBefore = getRuntimeMemoryInMegabytes();

		DSSDocument ltaLevelSignature = service.extendDocument(ltLevelSignature, params);

		double memoryLTALevelExtendDocument = getRuntimeMemoryInMegabytes();
		memoryConsumptions.add(memoryLTALevelExtendDocument - memoryBefore);
		LOG.info("[{}] Memory used for LTA-Level extendDocument() : {}Mb", pdfMemoryUsageSetting.getMode(), memoryLTALevelExtendDocument - memoryBefore);

		FileDocument ltaSignatureFileDocument = (FileDocument) ltaLevelSignature;
		File ltaSignatureFile = ltaSignatureFileDocument.getFile();
		return Pair.of(memoryConsumptions, ltaSignatureFile);
	}

	private void attemptFreeRuntimeMemory() {
		Runtime.getRuntime().gc();
		LOG.debug("Freeing up memory..");
		Runtime.getRuntime().gc(); // Empirically it is required to do more calls in order to properly clean-up
	}

	private static double getRuntimeMemoryInMegabytes() {
		// Get the Java runtime
		Runtime runtime = Runtime.getRuntime();
		// Calculate the used memory
		double memory = runtime.totalMemory() - runtime.freeMemory();
		return bytesToMegabytes(memory);
	}

	private static double bytesToMegabytes(double bytes) {
		return bytes / (1024L * 1024L);
	}

	@Override
	protected PAdESService getService() {
		return service;
	}

	@Override
	protected PAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
